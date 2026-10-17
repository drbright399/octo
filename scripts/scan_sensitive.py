#!/usr/bin/env python3
"""scan_sensitive.py: the ONE scanner for secrets and never-public strings.

Used by ``.githooks/pre-commit`` (``--staged --publish``), ``.githooks/commit-msg``
(``--message --publish``), ``.githooks/pre-push`` (``--range --publish`` and
``--ref-name --publish``), ``scripts/publish_public.sh`` (``--publish``) and by
hand (``--tree``, ``--all-history``). The detectors live in
``apps/octo/security/secret_patterns.py`` and are shared with runtime
redaction of Datto job output, so a shape added there is caught everywhere.

The public standard applies to the private repo too (Rick, 2026-10-15): the
hooks run the strict ``--publish`` checks on every commit, message and push,
and ``--tree --publish`` over the private tree is expected to be clean.

Modes (pick one; ``--publish`` alone means "the tree, strictest"):

  --staged          the index: lines added by the commit being made
  --message FILE    a commit message (the commit-msg hook): what git will
                    keep. Comment lines are checked too (``git commit -m`` /
                    ``-F`` and cleanup=whitespace|verbatim keep them); they
                    are dropped only when an editor ran and git's own
                    template says it strips them (the LAST "will be ignored"
                    hint, right under git's "Please enter the commit message"
                    line, and no "will be kept" hint). The comment string is
                    git's, from its configuration (core.commentChar /
                    core.commentString, ``#`` by default; ``auto``: one of
                    git's candidates), never one the text names, and
                    commit.cleanup=whitespace|verbatim strips nothing.
                    Everything below git's scissors block (``git commit -v``:
                    the cut line and git's two explanation lines under it) is
                    ignored when git's -v diff follows it (after comment
                    lines only), or, with commit.cleanup=scissors, when only
                    comment lines do; a scissors line alone may have been
                    typed and is not honoured, nor is a block followed by
                    other text, nor any without an editor (``GIT_EDITOR=:``,
                    -m / -F)
  --range A..B      every commit in A..B (what a push sends): the lines each
                    commit adds, its message, and the name and message of an
                    annotated tag at B (nested tags too: a tag object records
                    its own name, whatever name it is pushed under). With
                    ``--remote-tips FILE`` (the pre-push hook: ``git
                    ls-remote`` of the location being pushed to), commits
                    reachable from what the remote holds under ANY of its
                    refs are skipped, so moving a branch to commits pushed
                    elsewhere checks nothing again, while a commit the remote
                    no longer holds is checked again; an empty file = the
                    remote holds nothing. ``--remote NAME`` does the same from
                    this clone's remote-tracking refs (can be stale; a URL is
                    known to hold nothing). ``--range B`` alone = every commit
                    reachable from B that is not on the remote yet (default:
                    not on any remote-tracking ref)
  --ref-name NAME   a ref name a push would create on the remote (branch or
                    tag; repeatable): a local-block term or a secret shape in
                    it is as public as one in a file, and with ``--publish``
                    so is an IP, an e-mail address, a home path or a ticket
                    number. A word-bounded term (``\\<acme\\>``) is also found
                    where ``_`` or digits join it to the rest of the name
                    (``acme_fix``, ``acme2``)
  --tree            the working tree (tracked + untracked, not ignored)
  --all-history     every object the repository holds: each blob and commit
                    message reachable from ``git rev-list --all --reflog
                    --indexed-objects`` (stashes and every worktree's index
                    included), annotated tags, and the unreachable commits,
                    tags, trees and blobs ``git fsck --unreachable
                    --no-reflogs`` reports (dropped stashes, amended or
                    rebased-away commits, blobs that were staged and never
                    committed). Each blob is scanned once (by object id), under
                    the name with the STRICTEST rules among every name history
                    gave it (a source name before a lockfile, a generated or a
                    binary-extension name); a blob no tree names is
                    ``<unreachable>/<blob id, 12 hex>``. Every file name
                    history ever carried is checked too. Findings carry the
                    blob (or commit / tag) id. Read-only.
  --publish         also LAN / tailnet / public IPs (documentation ranges
                    excepted), home and /mnt paths, double-bracket memory links,
                    paths into an agent memory store (.claude/projects/<slug>/
                    memory, any prefix) and home-directory project slugs
                    (-home-<user>, -Users-<user>, C--Users-<user>),
                    *.ts.net names, e-mail addresses (not in dependency
                    lockfiles: package-lock.json, yarn.lock, pnpm-lock.yaml,
                    poetry.lock, uv.lock and Cargo.lock name third-party
                    authors in license metadata; secrets in them are still
                    found), NextDNS profile ids, opaque tokens in URL paths
                    (vendor deep links), PSA ticket numbers (T + date + . +
                    4 digits; T20000101.0001 is the fixture), and any binary
                    file that is not an image or a font. A modifier for every
                    mode above; alone, the tree. Combine with ``--root DIR``
                    to scan an export directory.

Always on, every mode: the detectors in ``secret_patterns`` (on contents and
on path names), files that must never be committed (key files, vaults,
``.env`` with values, databases outside fixtures, backups), and the local
sensitive-terms file ``.githooks/.local-block`` (gitignored; one term or regex
per line, ``#`` comments; client names, host names, tailnet ids). UTF-16 /
UTF-32 text is decoded; UTF-8 text with a stray NUL (which git calls binary)
is read as text; other binary content is searched for local-block terms and
secret shapes in its strings. Lines are never cut: a value 100 000 characters
into a minified line is found like one at the start. The terms file is found
in the checkout, in the main checkout of a linked worktree, or at
``$SCAN_SENSITIVE_LOCAL_BLOCK``;
that variable or ``--local-block`` naming a missing file is an error (exit 2).
With no terms at all the scan still runs (secret shapes only) and says so on
stderr; ``--no-local-block`` is the explicit opt-out.

An intentional, visibly-fake value can be allowed with an inline marker on
the same line, or on a comment line directly above it::

    x = "..."  # scan-sensitive: allow <why this value is safe>
    # scan-sensitive: allow[ip-private,email-address] <why these are safe>

A bare ``allow`` covers the secret detectors only; a publish-only detector
(IPs, e-mails, paths, ...) is allowed only by naming it in ``allow[...]``. The
reason is required and is read from the comment alone; a marker without one
is itself a finding. In ``--staged`` / ``--range`` a marker on the line above
covers its value only when the marker line is part of the same change. Local-
block terms can never be allowed inline.

A file whose content cannot be read (an added or changed blob git cannot
produce, a listed --tree file that cannot be opened) is a finding
(``unreadable-file``), never skipped. Blobs of --staged / --range are read by
object id, and file names that are not UTF-8 are kept byte for byte
(surrogateescape) and printed with U+FFFD in place of the bad bytes.

Output is ``path:line: [detector] col N: excerpt`` (``col`` for a line's
content only) with every hit MASKED, and with it every other word of 8+
characters on that line (its prose punctuation and paired brackets aside)
that mixes two of letters, digits and symbols (``Xxxxxx1!``) unless it is a
plain name, a version, a date, a host, a path or an option, whatever is
glued to a hit through ``:`` / ``%`` / ``=``,
and in a word that holds a hit every piece of 6+ characters between field
separators (``, ; / \\ @ = :``) that is not a plain name or a number (a
password in a CSV row or a ``user:pw@host`` next to an IP): the full value is
never printed. A run of non-blanks with a quote inside it is judged as one
word too (``Xk9m'Q2p!zR``), a short value after ``name=`` together with its
name (``aa=9#^aa$a``), a short core with its brackets or its last comma
(``(Xk9mQ2p)``), so a password is not printed in pieces too short to count.
A never-public value in the path column (an IP, an e-mail
address in a file name) is masked the same way.
A detector check that raises on some input is a bug: that candidate is no
hit for that detector, every other detector still runs, and a warning on
stderr names the detector, never the value. Any other internal error refuses
with exit 2 and the exception's type only (``SCAN_SENSITIVE_DEBUG=1`` shows
the traceback, which may quote a value).
Exit 0 = clean, 1 = findings, 2 = usage / git / internal error.
"""
from __future__ import annotations

import argparse
import bisect
import fnmatch
import functools
import os
import re
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Iterator, Optional

try:
    import re._parser as _sre_parser  # Python 3.11+
except ImportError:  # pragma: no cover - older Pythons
    import sre_parse as _sre_parser  # type: ignore[no-redef]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
if __name__ == "__main__":
    # A hook runs this from the work tree: leave no __pycache__ there for a
    # `git add -A` to pick up (a .pyc is a binary the --publish checks refuse).
    sys.dont_write_bytecode = True

from apps.octo.security import secret_patterns as sp  # noqa: E402

LOCAL_BLOCK_REL = ".githooks/.local-block"
#: Bumped when the detectors or the hooks change, so a hook pinned by
#: scripts/install_hooks.sh can tell that the work tree carries a newer one.
#: 4 (2026-10-15): the hooks run --publish; the sweep's new shapes; --all-history.
#: 5 (2026-10-15): pre-push skips commits already on the remote under any ref;
#: ref names get the publish checks; psa-ticket-id and cli-password; '#' lines
#: of a message are checked; wider excerpt masking; versioned, atomic pinning.
#: 6 (2026-10-15): pre-push asks the remote what it holds (ls-remote ->
#: --remote-tips); one cli-password detector per option shape, and the MSP
#: forms (ConvertTo-SecureString, plink -pw, sqlcmd -P, ...); IPs joined by
#: '_'; ref names judged before overlaps; git's exact scissors block only;
#: hit words masked piece by piece; installs serialized by a lock.
#: 7 (2026-10-15): pre-push fetches the remote tips this clone lacks (objects
#: only, no refs) and says to fetch when it cannot; docker login and every
#: option list match one way (ReDoS); a check that raises is no hit (scan) or
#: scrubbed (redact), never a crash; excerpts mask any 8+ word mixing two
#: character classes; PowerShell / cmd expansions are no cli-password; only
#: git's own scissors block and strip hint are trusted.
#: 8 (2026-10-16): no quadratic redaction or scan on runs of rejected
#: candidates (bounded option values, lookbehinds on token shapes); blobs read
#: by object id and an unreadable one is a finding (non-UTF-8 file names);
#: the commit message's comment string comes from git's configuration; a
#: quote inside a word or a short name=value no longer splits a password
#: into readable pieces.
#: 9 (2026-10-16): memory-path (--publish): a link or path into an agent's
#: memory store (the memory directory of a .claude/projects/<slug>/ entry,
#: any prefix, '/' or '\') and a home-directory project slug on its own
#: (-home-<user>, -Users-<user>, C--Users-<user>).
GUARDRAILS_VERSION = 10
COMMIT_MESSAGE = "<commit-message>"
TAG_MESSAGE = "<tag-message>"
TAG_NAME = "<tag-name>"
REF_NAME = "<ref-name>"
UNREACHABLE = "<unreachable>"
LOCAL_BLOCK_ENV = "SCAN_SENSITIVE_LOCAL_BLOCK"
#: =1: let an internal error raise with its traceback (which may quote a value).
DEBUG_ENV = "SCAN_SENSITIVE_DEBUG"

_FIXTURE_PATH = re.compile(r"(?:^|/)(?:fixtures?|testdata|test_data|__fixtures__)/")
_GENERATED = re.compile(
    r"(?:^|/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock"
    r"|Pipfile\.lock|uv\.lock|Cargo\.lock|go\.sum)$|\.min\.(?:js|css)$|\.map$|\.tsbuildinfo$"
)
_BINARY_EXT = re.compile(
    r"\.(?:png|jpe?g|gif|webp|ico|icns|bmp|tiff?|pdf|woff2?|ttf|otf|eot|mp[34]|mov|wav|ogg"
    r"|pmtiles|mbtiles|pbf|wasm|so|dylib|dll|exe|bin|pyc|class|jar)$",
    re.I,
)
# The only binary types a public copy may carry: images and fonts. Anything
# else binary cannot be read for secrets or client names, so --publish refuses it.
_PUBLISH_BINARY_OK = re.compile(
    r"\.(?:png|jpe?g|gif|webp|ico|icns|bmp|woff2?|ttf|otf|eot)$", re.I
)

# Files that must never be committed, whatever they contain.
_NEVER = (
    ("key-file", re.compile(r"\.(?:pem|key|p12|pfx|jks|keystore|ppk|kdbx|ovpn)$", re.I)),
    ("ssh-key-file", re.compile(r"(?:^|/)id_[A-Za-z0-9_]+$")),
    ("encrypted-vault-file", re.compile(r"\.(?:gpg|pgp|age)$|\.gpg\.", re.I)),
    ("credential-store-file", re.compile(
        r"(?:^|/)(?:\.netrc|_netrc|\.pgpass|\.htpasswd|credentials\.json"
        r"|service-account[^/]*\.json|terraform\.tfstate(?:\.backup)?)$"
    )),
    ("local-terms-file", re.compile(r"(?:^|/)\.githooks/\.(?:local-block|publish-map)$")),
    ("database-file", re.compile(r"\.(?:db|sqlite|sqlite3|db-wal|db-shm|db-journal)$", re.I)),
    ("backup-file", re.compile(
        r"\.(?:bak|backup|old|orig|dump|sql\.gz|tar|tar\.gz|tgz|zip|7z|rar)$|~$|\.sw[op]$", re.I
    )),
)
_ENV_FILE = re.compile(
    r"(?:^|/)(?:\.env|[^/]+\.env)"
    r"(?:\.(?!(?:py|ts|tsx|js|jsx|sh|md|json|ya?ml|toml)$)[^/.]+)?$"  # not settings.env.py
)
_ENV_EXAMPLE = re.compile(r"\.(?:example|template|sample|dist|defaults|tmpl)$", re.I)
_ENV_ASSIGN = re.compile(
    r"^[ \t]*(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*(?P<v>[^#\n]*)", re.M
)

_MARKER = re.compile(
    re.escape(sp.ALLOW_MARKER) + r"(?:\[(?P<scope>[^\]\n]{0,400})\])?(?P<reason>[^\n]*)"
)
# Where a comment ends: the reason is the text before it, never the code after.
# HTML / XML / SVG / Markdown "-->", and "--!>", which ends a comment in an
# HTML parser too (CodeQL py/bad-tag-filter); "*/" (C-style, JSX "{/* */}");
# docstring quotes; Jinja "#}" "%}"; Smarty "*}"; Handlebars / Mustache "}}";
# ERB / EJS / ASP "%>". Cutting too early only shortens the reason (a marker
# then needs its reason inside the comment), never lengthens it.
# Case-insensitive, though no end has a letter today.
_COMMENT_END = re.compile(r"--!?>|\*/|\"\"\"|'''|#\}|%\}|\*\}|\}\}|%>", re.I)
_MARKER_ONLY_LINE = re.compile(
    r"^\s*(?:#|//|/\*+|\*|<!--|--|;|rem\b|::|\{/\*)?\s*" + re.escape(sp.ALLOW_MARKER), re.I
)
_POSIX_CLASSES = {
    "[:alpha:]": "A-Za-z", "[:digit:]": "0-9", "[:alnum:]": "A-Za-z0-9", "[:upper:]": "A-Z",
    "[:lower:]": "a-z", "[:space:]": r"\s", "[:xdigit:]": "0-9A-Fa-f", "[:punct:]": r"!-/:-@\[-`{-~",
}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int  # 0 = the file itself
    detector: str
    excerpt: str
    commit: str = ""
    column: int = 0  # 1-based, in the line; 0 = not about a line's content

    def render(self) -> str:
        where = f"{self.commit[:10]} " if self.commit else ""
        col = f"col {self.column}: " if self.column else ""
        return printable(f"{where}{self.path}:{self.line}: [{self.detector}] {col}{self.excerpt}")


_SURROGATE = re.compile("[\ud800-\udfff]")


def printable(text: str) -> str:
    """``text`` as it can be printed: a lone surrogate (a byte of a file name
    or a ref name that is not UTF-8, kept by surrogateescape) becomes U+FFFD.
    Printing it as is raises UnicodeEncodeError. Control characters (C0, DEL,
    C1: an ESC sequence in a crafted file name could rewrite the report on a
    terminal) are shown escaped, e.g. \\x1b."""
    return _UNPRINTABLE.sub(lambda m: "\\x%02x" % ord(m.group()), _SURROGATE.sub("\ufffd", text))


_UNPRINTABLE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


# --------------------------------------------------------------------------- #
# Local sensitive terms
# --------------------------------------------------------------------------- #

def _translate_ere(term: str) -> str:
    for posix, py in _POSIX_CLASSES.items():
        term = term.replace(posix, py)
    return term.replace(r"\<", r"\b").replace(r"\>", r"\b")


def required_literal(term: str) -> str:
    """Lower-cased ASCII text every match of ``term`` contains: the longest
    run of literal characters in its top-level sequence (3+), or "" when no
    such run is certain (an alternation, a group, a class at every step)."""
    try:
        parsed = _sre_parser.parse(term, re.I)
    except Exception:  # re.error, or a parser that changed shape: no prefilter
        return ""
    best = run = ""
    for op, arg in parsed:
        if op is _sre_parser.LITERAL and arg < 128:
            run += chr(arg).lower()
        else:
            best, run = max(best, run, key=len), ""
    best = max(best, run, key=len)
    return best if len(best) >= 3 else ""


def _has_backref(term: str) -> bool:
    """True when ``term`` holds a back-reference (``\\1``, ``(?P=name)``,
    ``(?(1)a|b)``) or cannot be parsed: either way, no prefilter."""
    try:
        parsed = _sre_parser.parse(term, re.I)
    except Exception:
        return True
    refs = {_sre_parser.GROUPREF, _sre_parser.GROUPREF_EXISTS}
    stack = [parsed]
    while stack:
        for op, arg in stack.pop():
            if op in refs:
                return True
            for item in (arg if isinstance(arg, (list, tuple)) else (arg,)):
                if isinstance(item, _sre_parser.SubPattern):
                    stack.append(item)
                elif isinstance(item, (list, tuple)):
                    stack.extend(x for x in item if isinstance(x, _sre_parser.SubPattern))
    return False


class LocalBlock:
    """The local-block terms: one case-insensitive alternation (``pattern``)
    that ``search`` / ``finditer`` run only over text that holds at least one
    term's required literal, and then only with those terms (plus any term
    without a literal). An alternative that cannot match anywhere in a text
    never changes which match the alternation finds, so the results are the
    full pattern's; the hooks and the history scan skip most of the cost."""

    def __init__(self, parts: list[str]) -> None:
        self.parts = parts
        self.pattern = re.compile("|".join(f"(?:{p})" for p in parts), re.I)
        self._by_literal: dict[str, list[int]] = {}
        always: set[int] = set()
        # A back-reference by number (\1, (?(1)...)) counts groups across the
        # whole alternation: a subset would renumber them and change what a
        # term matches. With any back-reference, every text gets the full pattern.
        exact = not any(_has_backref(part) for part in parts)
        for i, part in enumerate(parts):
            literal = required_literal(part) if exact else ""
            if literal:
                self._by_literal.setdefault(literal, []).append(i)
            else:
                always.add(i)
        self._always = frozenset(always)
        self._subsets: dict[tuple[int, ...], "re.Pattern[str]"] = {}

    def _pattern_for(self, text: str) -> Optional["re.Pattern[str]"]:
        folded = sp.fold_lower(text)  # what re.IGNORECASE folds to ASCII, folded first
        chosen = set(self._always)
        for literal, ids in self._by_literal.items():
            if literal in folded:
                chosen.update(ids)
        if not chosen:
            return None
        if len(chosen) == len(self.parts):
            return self.pattern
        key = tuple(sorted(chosen))  # the file's order: the same alternative wins a tie
        rx = self._subsets.get(key)
        if rx is None:
            rx = re.compile("|".join(f"(?:{self.parts[i]})" for i in key), re.I)
            if len(self._subsets) < 512:
                self._subsets[key] = rx
        return rx

    def search(self, text: str) -> Optional["re.Match[str]"]:
        rx = self._pattern_for(text)
        return None if rx is None else rx.search(text)

    def finditer(self, text: str) -> Iterator["re.Match[str]"]:
        rx = self._pattern_for(text)
        return iter(()) if rx is None else rx.finditer(text)


def load_local_block(path: Optional[Path]) -> Optional[LocalBlock]:
    """Every term in the local-block file, matched case-insensitively (see
    :class:`LocalBlock`). A line that is not a valid regex is matched
    literally; a pattern that would match the empty string is skipped (it
    would hit everywhere)."""
    if path is None or not path.is_file():
        return None
    parts: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        term = raw.strip()
        if not term or term.startswith("#"):
            continue
        candidate = _translate_ere(term)
        try:
            compiled = re.compile(candidate, re.I)
        except re.error:
            candidate = re.escape(term)
            compiled = re.compile(candidate, re.I)
        if compiled.search(""):
            print(f"scan-sensitive: local-block line skipped (matches empty text): {sp.mask(term)}",
                  file=sys.stderr)
            continue
        parts.append(candidate)
    return LocalBlock(parts) if parts else None


def default_local_block(root: Path) -> Optional[Path]:
    """``<root>/.githooks/.local-block``; in a linked worktree, the main
    checkout's file (worktrees do not carry gitignored files).
    ``$SCAN_SENSITIVE_LOCAL_BLOCK`` wins; ``main()`` refuses (exit 2) when it
    names a file that does not exist, never a silent "no terms"."""
    env = os.environ.get(LOCAL_BLOCK_ENV)
    if env:
        return Path(env)
    own = root / LOCAL_BLOCK_REL
    if own.is_file():
        return own
    common = _git(root, "rev-parse", "--path-format=absolute", "--git-common-dir", check=False, paths=True)
    if common:
        shared = Path(common.strip()).parent / LOCAL_BLOCK_REL
        if shared.is_file():
            return shared
    return None


# --------------------------------------------------------------------------- #
# Scanning one file
# --------------------------------------------------------------------------- #

def _is_binary(data: bytes) -> bool:
    return decode_text(data) is None


_BOMS = (
    (b"\xef\xbb\xbf", "utf-8"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
)


def decode_text(data: bytes) -> Optional[tuple[str, str, bytes]]:
    """``(text, codec, bom)`` for text, ``None`` for binary. A BOM picks the
    codec (Windows PowerShell 5.1 ``Out-File`` / ``>`` writes UTF-16LE with
    one); NUL-interleaved ASCII without a BOM is UTF-16 too. Valid UTF-8 with
    a stray NUL or two (a NUL-terminated string, a pasted control character)
    is text as well: git calls it binary, so nothing else would read it."""
    for bom, codec in _BOMS:
        if data.startswith(bom):
            return data[len(bom):].decode(codec, "replace"), codec, bom
    head = data[:8192]
    if b"\0" not in head:
        return data.decode("utf-8", "replace"), "utf-8", b""
    if len(head) >= 4:
        even, odd = head[0::2], head[1::2]
        for zeros, other, codec in ((odd, even, "utf-16-le"), (even, odd, "utf-16-be")):
            if zeros.count(0) >= 0.9 * len(zeros) and other.count(0) <= 0.05 * len(other):
                return data.decode(codec, "replace"), codec, b""
    return _text_with_nuls(data)


# Control characters text does not carry (tab, newlines, form feed and ESC do).
_CONTROL = re.compile(r"[\x00-\x08\x0e-\x1a\x1c-\x1f\x7f]")


def _text_with_nuls(data: bytes) -> Optional[tuple[str, str, bytes]]:
    """Strict UTF-8 whose control characters (NUL included) are at most 1%
    of it (4 in a short file): text. The NULs stay, so offsets, lines and a
    re-encode match the bytes. Compiled code, archives and databases fail
    one test or the other."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    limit = max(4, len(text) // 100)
    for count, _ in enumerate(_CONTROL.finditer(text), 1):
        if count > limit:
            return None
    return text, "utf-8", b""


_STRINGS = re.compile(rb"[\x20-\x7e]{6,}|(?:[\x20-\x7e]\x00){6,}")


def binary_strings(data: bytes) -> str:
    """The printable ASCII and UTF-16LE strings of binary content, one per
    line (what ``strings`` would show)."""
    out = []
    for m in _STRINGS.finditer(data):
        chunk = m.group(0)
        out.append(chunk.decode("utf-16-le", "replace") if chunk[1:2] == b"\0" else chunk.decode("ascii"))
    return "\n".join(out)


def _marker_reason(reason: str) -> str:
    """The reason, cut at the end of the comment that carries the marker."""
    end = _COMMENT_END.search(reason)
    return (reason[:end.start()] if end else reason).strip(" \t:-–—")


def _marker_reason_ok(reason: str) -> bool:
    return re.search(r"[A-Za-z]{3,}", _marker_reason(reason)) is not None


@dataclass(frozen=True)
class _Allow:
    scope: Optional[frozenset[str]]  # None = every secret detector, never publish-only

    def covers(self, detector: str) -> bool:
        if detector == "local-block":
            return False
        if self.scope is None:
            return detector not in sp.PUBLISH_ONLY_NAMES
        return detector in self.scope


_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/_=.-]{20,}")
# A piece of a word that holds a hit: the word is cut only where fields are
# separated (CSV ',' / ';', user:pw, host/path, \\host\share, user@host,
# key=value) and at quotes. Brackets, '#', '%', '<>' and non-ASCII letters
# stay in: a password carries them, and "Xk9(mQ2)pL7v" is one value, not
# three pieces too short to count. Dots stay in too: a dotted name (a host)
# is judged whole.
_HIT_WORD_PIECE = re.compile(r"[^,;/\\@=:'\"`]+")
# sess1, backup2, dc01: a word with a short number is a name.
_NUMBERED_NAME = re.compile(r"_*[a-z]{1,12}\d{1,3}")
_SHORT_LABEL = re.compile(r"[a-z0-9_-]{1,3}|[A-Z0-9_-]{1,3}")
_CAPITALIZED = re.compile(r"[A-Z][a-z]+")
# A word of a line: what lies between blanks and quotes.
_WORD = re.compile(r"[^\s'\"`]+")
# A run of non-blanks: judged whole when a quote sits inside it (see below).
_RUN = re.compile(r"\S+")
# A quote inside a run that is no field or call boundary: something on each
# side, neither a quote nor a separator (, ; : =), no opening bracket before
# it and no closing one after it. Xk9m'Q2p!zR and yi)"0&S?4B have one;
# "a","b", {"k":"v"}, f("x") and ['x'] do not.
_INSIDE_QUOTE = re.compile(r"""(?<=[^\s'"`(\[{,;:=])['"`](?=[^\s'"`)\]},;:=])""")
_QUOTES = "'\"`"
_NO_QUOTES = str.maketrans("", "", _QUOTES)
_QUOTE_PIECE = re.compile(r"[^'\"`]+")
# A string literal's prefix before its opening quote (f"...", rb'...'), at
# the start of a run or after a bracket or a separator.
_STRING_PREFIX = re.compile(r"(?:^|(?<=[\s(\[{,;:=]))[rRbBuUfF]{1,2}$")
# The segments of a path or a URL before its query (judged whole as well as
# piece by piece: /1ut;N)GDp has no piece of 8).
_PATH_SEGMENT = re.compile(r"[^/\\?#]+")
# Edge punctuation a piece glued to a hit is judged without (_piece_value;
# it is still masked with it).
_EDGE = ".,:;!?()[]{}<>*_~"
# What a word on a reported line is judged without (_prose_core): the prose
# punctuation it ends with, and wrappers in matching pairs.
_PROSE_TAIL = ".,:;"
_PAIRS = {"(": ")", "[": "]", "{": "}", "<": ">", "'": "'", '"': '"', "`": "`"}
# v0.17.6, 1.2.3-rc.1, 2026-10-15, 2026-10-15T10:00:00Z: readable.
_VERSION_OR_DATE = re.compile(
    r"[vV]?[0-9]+(?:\.[0-9]+)+(?:[-+][0-9a-z]+(?:\.[0-9a-z]+)*)?"
    r"|[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T_ ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,9})?)?"
    r"(?:Z|[+-][0-9]{2}:?[0-9]{2})?)?"
)
_SIMPLE_SPLIT = re.compile(r"[.:/\\]")
_PATHLIKE = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*://|\.{0,2}/|~/|[A-Za-z]:\\|\\\\)")
# A URL or a path is judged piece by piece.
_PATH_PIECE = re.compile(r"[^/\\?&#=:@,;()\[\]{}<>]+")
# "name=value" / "name:value": the name stays readable, the value is judged.
_NAME_PREFIX = re.compile(r"([A-Za-z_][A-Za-z0-9_.-]{0,80})[=:](?!//)")
_NUMBERISH = re.compile(r"[0-9][0-9.:,/x+=-]*")  # versions, dates, times, sizes, sums
# What is glued to a hit through one of these is the rest of one value:
# user:<pw>, <key>:<secret>, user%<pw>, NAME=<v>.
_GLUE_AFTER = ":%="
_GLUE_BEFORE = ":%"
_GLUED_RUN = re.compile(r"[^\s'\"`/\\@,;()\[\]{}<>]+")
_GLUED_STOP = frozenset(" \t'\"`/\\@,;()[]{}<>:%=")
# Longer than this, a run glued to a hit is no name (and is not judged as one).
_NAME_MAX = 120


def _plain_name(part: str) -> bool:
    """A name a reader needs in the excerpt: snake / kebab / CONSTANT case,
    lower-case words, words joined by separators. Not camelCase (random
    mixed case passes for it) and not the dash groups of a license key."""
    if sp._key_groups(part):
        return False
    bare = part.lstrip("_")
    return bool(sp._IDENT_LIKE.match(part) or (bare.isalpha() and sp._wordlike(bare))
                or sp._made_of_words(part, need_vocab=False))


def _value_like(run: str) -> bool:
    """A leftover piece that could be a value: 12+ characters, or 8+ that mix
    letters with digits or upper with lower case, unless every dot-separated
    part of it is a plain name (a host name, ``default-dashboard``,
    ``ADAPTER_KEY_BASE64``)."""
    core = run.strip(".")
    if len(core) < 8 or all(len(p) <= 3 or _plain_name(p) for p in core.split(".") if p):
        return False
    return (len(core) >= 12 or (any(c.isdigit() for c in core) and any(c.isalpha() for c in core))
            or (any(c.isupper() for c in core) and any(c.islower() for c in core)))


def _hit_word_name(part: str) -> bool:
    """A name that may stay readable next to a hit (a user, a host label, a
    share, a path segment), judged more strictly than _plain_name: ASCII
    snake / kebab / CONSTANT case or a lower-case word, a capitalized word, a
    word with a short number (``backup2``), or a single-case label of up to
    3 characters (``v1``, ``dc``). Not camelCase, not words joined by ``+``,
    not non-ASCII letters: random text passes for those too easily."""
    return bool(_SHORT_LABEL.fullmatch(part) or _CAPITALIZED.fullmatch(part)
                or _NUMBERED_NAME.fullmatch(part)
                or (sp._IDENT_LIKE.match(part) and not sp._key_groups(part)))


def _piece_value(piece: str) -> bool:
    """A piece of a word that holds a hit (see _HIT_WORD_PIECE) that could
    be a value, or the readable rest of one: 6+ characters unless, edge
    punctuation aside (two characters at most: ``(admin)``, ``[dc01]``), it
    is a number, a date or a version, or every dot-separated part of it is a
    name (_hit_word_name: a user name, a host name, a share, a path
    segment). Stricter than for a word without a hit: camelCase, letters
    alone, non-ASCII letters and a run of punctuation around little else
    are masked too, since a password glued to a finding is the likeliest
    thing on such a line."""
    if len(piece) < 6:
        return False
    core = piece.strip(_EDGE)
    if len(piece) - len(core) > 2:
        return True
    if not core or _NUMBERISH.fullmatch(core):
        return False
    if _word_value(core) or _value_like(core):
        return True
    return not all(_hit_word_name(p) for p in core.split(".") if p)


def _leftover_values(line: str, start: int, end: int, spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """The parts of a word (or a long token) outside the hits it holds that
    could be values themselves: a password glued to a finding through ``,``
    ``;`` ``/`` ``@`` (a CSV row, ``user:pw@host``), a token in the path of a
    URL whose host is a hit, the rest of a value a local-block term sits in.
    The gaps between the hits are cut at field separators only and each
    piece is judged by _piece_value (Unicode-aware). Only a plain name stays
    readable (``ADAPTER_KEY_BASE64=`` before a hit, ``default-dashboard``, a
    host name, a user name); camelCase is masked too, since random
    mixed-case text can pass for it."""
    out: list[tuple[int, int]] = []
    pos = start
    for s, e in sorted(spans) + [(end, end)]:  # the gaps between the hits, then the tail
        if s > pos:
            for m in _HIT_WORD_PIECE.finditer(line, pos, min(s, end)):
                if _piece_value(m.group(0)):
                    out.append(m.span())
        pos = max(pos, e)
        if pos >= end:
            break
    return out


def _prose_core(word: str) -> str:
    """The word without the prose punctuation it ends with (``. , : ;``) and
    without paired wrappers around it (``(…)`` ``[…]`` ``{…}`` ``<…>``,
    quotes): what its length and its character classes are judged on.
    Nothing else comes off: a ``!`` ``*`` ``?`` ``~`` ``_`` or a lone bracket
    at an edge is part of the value (``Xxxxxx1!``, ``*Hq4zR8w``)."""
    lo, hi = 0, len(word)  # indices, not slices: "((((...))))" stays linear
    while True:
        while hi > lo and word[hi - 1] in _PROSE_TAIL:
            hi -= 1
        if hi - lo < 2 or _PAIRS.get(word[lo]) != word[hi - 1]:
            return word[lo:hi]
        lo, hi = lo + 1, hi - 1


def _simple_part(part: str) -> bool:
    return bool(_NUMBERISH.fullmatch(part)
                or (len(part) <= 3 and (part.isalpha() or _SHORT_LABEL.fullmatch(part)))
                or _plain_name(part))


def _simple_word(core: str) -> bool:
    """A word a reader needs and a password is not: a version or a date, an
    option (``--publish``), or a name, a host or a path (``~/`` too) whose
    every part between ``. : / \\`` is a plain name (_plain_name), a number or
    a short label (``src/app.py``, ``rmm.vendor.invalid``, ``db.local:5432``)."""
    if _VERSION_OR_DATE.fullmatch(core):
        return True
    body = core[2:] if core.startswith("--") else core[1:] if core.startswith(("-", "~/")) else core
    parts = [p for p in _SIMPLE_SPLIT.split(body) if p]
    return bool(parts) and all(_simple_part(p) for p in parts)


def _short_readable(core: str) -> bool:
    """A piece under 8 characters a reader needs: a number, a date, a
    version, a simple word (_simple_word) or a name (_hit_word_name: a user,
    a host label, ``dc01``, ``Debug``)."""
    return (not core or _NUMBERISH.fullmatch(core) is not None or _simple_word(core)
            or all(_hit_word_name(p) for p in core.split(".") if p))


def _opaque_short(core: str) -> bool:
    """A piece under 8 characters that mixes two of letters, digits and
    symbols and is no readable name or number (_short_readable): the rest of
    a password, never shown on its own (``9#^aa$a`` in ``aa=9#^aa$a``)."""
    if len(core) >= 8:
        return False
    classes = (any(c.isalpha() for c in core) + any(c.isdigit() for c in core)
               + any(not c.isalnum() for c in core))
    return classes >= 2 and not _short_readable(core)


def _word_value(piece: str) -> bool:
    """A word (or a piece of a URL, a path or a ``name=value``) that could be
    a value: 8+ characters, prose punctuation and paired wrappers aside
    (_prose_core), that mix two or more of letters, digits and symbols (any
    character that is neither: ``Xxxxxx1!``, ``pSa>ç)XmG``). Not one: a
    simple word (_simple_word: a plain name, a version, a date, a host, a
    path, an option). Letters alone are read as words, as everywhere else
    (``looks_real`` does the same): random mixed case cannot be told apart
    from camelCase at this length; so are letters with a quote inside
    (``shouldn't``). A shorter core in wrappers that make the word 8+
    (``(Xk9mQ2p)``: the brackets may be part of the password) counts when
    the core is no readable name or number (_opaque_short); so does one
    that prose punctuation makes 8+ (``Xk9#mQ2,``: the comma may be the
    password's last character)."""
    core = _prose_core(piece)
    if len(core) < 8:
        # Brackets and prose punctuation may be the password's own; a pair of
        # quotes around it and what follows them are not ("fe80::1",).
        body = piece.rstrip(_PROSE_TAIL)
        quoted = len(body) >= 2 and body[0] in _QUOTES and body[-1] == body[0]
        return (len(body) - 2 if quoted else len(piece)) >= 8 and _opaque_short(core)
    if _NUMBERISH.fullmatch(core) or core.translate(_NO_QUOTES).isalpha():
        return False
    letters = any(c.isalpha() for c in core)
    digits = any(c.isdigit() for c in core)
    symbols = any(not c.isalnum() for c in core)
    if letters + digits + symbols < 2:
        return False
    return not _simple_word(core)


def _word_masks(line: str, start: int, end: int) -> list[tuple[int, int]]:
    """The value-like parts of a word that holds no hit (see _word_value):
    the whole word, or, in a URL, a path or after a plain ``name=`` /
    ``name:``, each piece on its own, so a host, a path and a name stay
    readable. A piece is judged on its own only when it is 8+ or readable:
    a shorter value after ``name=`` (``aa=9#^aa$a``) or a short opaque piece
    of a path (``/Xk9#mQ2``) makes the whole word the unit, so no 7
    characters of a password are printed because a separator sat in it."""
    word_start = start
    for _ in range(4):
        m = _NAME_PREFIX.match(line, start, end)
        if m is None or not (_plain_name(m.group(1)) or len(m.group(1)) <= 3):
            break
        start = m.end()
    if start >= end:
        return []
    if start > word_start:
        rest = _prose_core(line[start:end])
        if len(rest) < 8:
            if _short_readable(rest) or rest.isalpha():
                return []  # port=5432, mode=fast, host=dc01, lang=enUS
            return [(word_start, end)] if _word_value(line[word_start:end]) else []
    if _PATHLIKE.match(line, start, end):
        pieces = list(_PATH_PIECE.finditer(line, start, end))
        if any(_opaque_short(_prose_core(p.group(0))) for p in pieces):
            return [(start, end)] if _word_value(line[start:end]) else []
        query = min((i for i in (line.find("?", start, end), line.find("#", start, end)) if i != -1),
                    default=end)
        masks = ([p.span() for p in pieces if _word_value(p.group(0))]
                 + [g.span() for g in _PATH_SEGMENT.finditer(line, start, query) if _word_value(g.group(0))])
        if not masks and "://" not in line[start:end] and _word_value(line[start:end]):
            masks.append((start, end))  # a file path with no part of 8 (/pUmh;4L, ~/a5u#BILe)
        return masks
    return [(start, end)] if _word_value(line[start:end]) else []


def _glued_masks(line: str, start: int, end: int,
                 hits: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """In a word that holds a hit: the run glued to the hit's end through
    ``:`` ``%`` ``=`` (the rest of ``<key>:<secret>``, ``user%<pw>``), unless
    it is a port number, and the run glued to its start through ``:`` /
    ``%`` (``<pw>:<hit>``), unless it is a plain name (a user name).

    Linear in the word however many hits it holds (``<key>=<key>=...`` on
    one 50 kB line): a run that starts inside the last one found ends where
    it ends, a walk back that reaches the last walk's start goes on as it
    did, and a run longer than any name is no name without judging it."""
    out: list[tuple[int, int]] = []
    run_from = run_to = -1    # the last run found after a hit: [run_from, run_to)
    back_from = back_to = -1  # the last walk back: from back_from down to back_to
    for s, e in hits:
        if e < end and line[e] in _GLUE_AFTER:
            p = e + 1
            if not run_from <= p < run_to:
                m = _GLUED_RUN.match(line, p, end)
                run_from, run_to = p, (m.end() if m is not None else p)
            if run_to > p and not (run_to - p <= 5 and line[p:run_to].isdigit()):
                out.append((p, run_to))
        if s > start and line[s - 1] in _GLUE_BEFORE:
            i = s - 1
            while i > start and line[i - 1] not in _GLUED_STOP:
                if i == back_from:
                    i = back_to
                    break
                i -= 1
            back_from, back_to = s - 1, i
            if i < s - 1 and (s - 1 - i > _NAME_MAX or not _plain_name(line[i:s - 1])):
                out.append((i, s - 1))
    return out


class _Spans:
    """The hits of one line, merged where they overlap (so starts and ends
    are both sorted), for "which hits overlap [a, b)" in O(log n): a
    minified line can carry thousands of hits and of words."""

    def __init__(self, spans: list[tuple[int, int]]) -> None:
        merged: list[list[int]] = []
        for start, end in sorted(spans):
            if merged and start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        self.spans = [(s, e) for s, e in merged]
        self.starts = [s for s, _ in self.spans]
        self.ends = [e for _, e in self.spans]

    def overlapping(self, a: int, b: int) -> list[tuple[int, int]]:
        lo = bisect.bisect_right(self.ends, a)  # the first span that ends after a
        hi = bisect.bisect_left(self.starts, b)
        return self.spans[lo:hi]


def _quote_split(run: str) -> bool:
    """A run of non-blanks whose quotes may be part of a value: one inside
    it (_INSIDE_QUOTE), a single one at an edge (``cRl@I5k'``), or a piece
    between quotes that is a short opaque value
    once its edge punctuation is off (``#Z)8zS('*k``). A quoted word, CSV
    fields and a call's quoted argument are none of these."""
    quotes = sum(run.count(q) for q in _QUOTES)
    if not quotes:
        return False
    body = run.rstrip(_PROSE_TAIL)
    if len(body) >= 2 and body[0] in _QUOTES and body[-1] == body[0]:
        body = body[1:-1]
    elif quotes == 1 and (body[:1] in _QUOTES or body[-1:] in _QUOTES):
        # One quote at an edge: the end of a quoted phrase ("Example Office",)
        # around a word, or the last character of a password (cRl@I5k').
        inner = body.strip(_QUOTES)
        return _opaque_short(inner) or _word_value(inner)
    for m in _INSIDE_QUOTE.finditer(body):
        # A prefix is at most three characters long: a window, never the
        # whole run before each quote (f"f"f"... would be quadratic).
        if not _STRING_PREFIX.search(body, max(0, m.start() - 3), m.start()):
            return True
    # name="value", ["a"], ("D0A1", ...): a name, brackets and a short id
    # around the quotes are no value of their own; a piece with a symbol is.
    for p in _QUOTE_PIECE.finditer(body):
        piece = p.group(0).strip(_EDGE + "=:")
        if _opaque_short(piece) and (len(piece) >= 6 or not piece.isalnum()):
            return True
    return False


def _excerpt(line: str, spans: list[tuple[int, int]], focus: int) -> str:
    """The line with every hit masked, and with it every value-like word of
    8+ characters mixing two character classes (a secret no detector named
    must not ride along in the excerpt; see _word_value; a run of non-blanks
    with a quote inside it is such a word too), every token of
    20+, and what is glued to a
    hit, cut to a window around ``focus``. A word that a hit covers only in
    part keeps none of its value-like rest readable."""
    covered = list(spans)
    index = _Spans(spans)
    for r in _RUN.finditer(line):
        # Quotes split a run into words that may each be too short to count
        # (Xk9m'Q2p!zR): the run is judged as one word too (_quote_split).
        if _quote_split(r.group(0)) and _word_value(r.group(0)):
            covered.append(r.span())
    for m in _LONG_TOKEN.finditer(line):
        overlapping = index.overlapping(m.start(), m.end())
        if not overlapping:
            covered.append(m.span())
        else:
            covered += _leftover_values(line, m.start(), m.end(), overlapping)
    for w in _WORD.finditer(line):
        ws, we = w.span()
        inside = index.overlapping(ws, we)
        if inside:
            covered += _glued_masks(line, ws, we, inside)
            covered += _leftover_values(line, ws, we, inside)
        else:
            covered += _word_masks(line, ws, we)
    # Overlapping hits are merged: a short hit (a local-block term) at the
    # start of a longer one (a password that begins with it) must not leave
    # the rest of the longer one readable.
    merged: list[list[int]] = []
    for start, end in sorted(covered):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    out: list[str] = []
    pos = 0
    shift = 0
    for start, end in merged:
        out.append(line[pos:start])
        masked = sp.mask(line[start:end])
        out.append(masked)
        if start < focus:
            shift += len(masked) - (end - start)
        pos = end
    out.append(line[pos:])
    text = "".join(out).replace("\t", " ").rstrip()
    centre = focus + shift
    lo = max(0, centre - 60)
    hi = min(len(text), centre + 80)
    return ("…" if lo else "") + text[lo:hi].strip() + ("…" if hi < len(text) else "")


def _mask_spans(text: str, spans: Iterable[tuple[int, int]]) -> str:
    """``text`` with every span masked; overlapping spans are merged first,
    so no part of a longer hit is left readable next to a shorter one."""
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    if not merged:
        return text
    out: list[str] = []
    pos = 0
    for start, end in merged:
        out.append(text[pos:start])
        out.append(sp.mask(text[start:end]))
        pos = end
    out.append(text[pos:])
    return "".join(out)


# In a NAME, '_' and digits join words for \b (and so for \< \>): a word-bounded
# term would miss acme_fix or acme2. Read as '-', they separate (same length,
# so the spans line up with the name).
_NAME_JOINERS = re.compile(r"[_0-9]")


def _local_name_spans(name: str, local: Optional[LocalBlock]) -> list[tuple[int, int]]:
    """Local-block hits in a ref / tag name, also where ``_`` or digits join a
    word-bounded term to the rest of the name."""
    if local is None:
        return []
    spans = {m.span() for m in local.finditer(name) if m.end() > m.start()}
    loose = _NAME_JOINERS.sub("-", name)
    if loose != name:
        spans |= {m.span() for m in local.finditer(loose) if m.end() > m.start()}
    return sorted(spans)


def display_path(path: str, local: Optional[LocalBlock],
                 extra: Iterable[tuple[int, int]] = ()) -> str:
    """The path (or ref name) as it may be printed: a secret, a never-public
    value (an IP, an e-mail address, a ticket number: the publish-only
    detectors, in every mode) or a local-block term in it is masked like one
    in contents (``extra``: more spans to mask)."""
    spans = [(h.start, h.end) for h in sp.find_hits(path, sp.Context(path=path), "scan", publish=True)]
    if local is not None:
        spans += [m.span() for m in local.finditer(path) if m.end() > m.start()]
    spans += list(extra)
    return _mask_spans(path, spans)


def _shown(found: list[Finding], path: str, local: Optional[LocalBlock]) -> list[Finding]:
    if not found:
        return found
    shown = display_path(path, local)
    return found if shown == path else [replace(f, path=shown) for f in found]


def path_findings(
    path: str,
    data: Optional[bytes],
    local: Optional[LocalBlock],
    *,
    publish: bool = False,
) -> list[Finding]:
    """Findings about the file itself (line 0): its type, its name (a token
    in a file name is as public as one in its contents) and, for an .env
    file, whether it carries values."""
    found: list[Finding] = []
    for name, rx in _NEVER:
        if not rx.search(path):
            continue
        if name == "database-file" and _FIXTURE_PATH.search(path):
            continue
        if name == "ssh-key-file" and path.endswith(".pub"):
            continue
        found.append(Finding(path, 0, f"forbidden-file:{name}", "this file type is never committed"))
    if _ENV_FILE.search(path) and not _ENV_EXAMPLE.search(path) and data is not None:
        text = data.decode("utf-8", "replace")
        if any(not sp.looks_placeholder(m.group("v").strip().strip("'\""))
               for m in _ENV_ASSIGN.finditer(text) if m.group("v").strip().strip("'\"")):
            found.append(Finding(path, 0, "forbidden-file:env-with-values",
                                 "an .env file with values; commit an .env.example with placeholders"))
    if local is not None and local.search(path):
        found.append(Finding(path, 0, "local-block", "the file path contains a local-block term"))
    seen: set[str] = set()
    for h in sp.find_hits(path, sp.Context(path=path), "scan", publish=publish):
        if h.detector not in seen:
            seen.add(h.detector)
            found.append(Finding(path, 0, f"path:{h.detector}",
                                 "the file path contains " + sp.mask(h.value)))
    return _shown(found, path, local)


# Integrity hashes in dependency lockfiles: SRI strings (npm, yarn, pnpm:
# sha512-<base64>), "sha256:<hex>" (poetry, uv) and Cargo's 64-hex checksum.
_LOCKFILE_HASH = re.compile(
    r"\bsha(?:1|224|256|384|512)[-:][A-Za-z0-9+/]{16,}={0,2}"
    r"|(?<=checksum = \")[0-9a-f]{64}(?=\")"
)


def scan_text(
    path: str,
    text: str,
    *,
    publish: bool = False,
    local: Optional[LocalBlock] = None,
    only_lines: Optional[set[int]] = None,
) -> list[Finding]:
    """Content findings for one file. ``only_lines`` (1-based) limits the
    report to those lines (a diff's added lines); markers are still read from
    the whole file."""
    ctx = sp.Context(path=path, generated=bool(_GENERATED.search(path)))
    hits = sp.find_hits(text, ctx, "scan", publish=publish)
    local_hits: list[sp.Hit] = []
    if local is not None:
        local_hits = [sp.Hit("local-block", m.start(), m.end(), m.group(0), False)
                      for m in local.finditer(text) if m.end() > m.start()]
        if local_hits and sp.LOCKFILE.search(path):
            # A dependency lockfile's integrity hashes are random base64 / hex:
            # a short term turns up inside them by chance (one in a few hundred
            # hashes for a 3-character term). A match wholly inside such a hash
            # is not a name; the same term anywhere else in the lockfile (a
            # package name, a URL) is still a finding.
            spans = [(h.start(), h.end()) for h in _LOCKFILE_HASH.finditer(text)]
            if spans:
                starts_h = [s for s, _ in spans]
                def _in_hash(hit: "sp.Hit") -> bool:
                    i = bisect.bisect_right(starts_h, hit.start) - 1
                    return i >= 0 and spans[i][0] <= hit.start and hit.end <= spans[i][1]
                local_hits = [h for h in local_hits if not _in_hash(h)]
    marker_lines = text.count(sp.ALLOW_MARKER)
    if not hits and not local_hits and not marker_lines:
        return []

    starts = [0] + [m.end() for m in re.finditer("\n", text)]
    lines = text.split("\n")

    def line_of(offset: int) -> int:
        return bisect.bisect_right(starts, offset)  # 1-based

    allowed: dict[int, list[_Allow]] = {}
    found: list[Finding] = []
    for m in _MARKER.finditer(text):
        ln = line_of(m.start())
        reported = only_lines is None or ln in only_lines
        scope: Optional[frozenset[str]] = None
        if m.group("scope") is not None:
            names = frozenset(n.strip() for n in m.group("scope").split(",") if n.strip())
            unknown = sorted(names - sp.REPORTED_NAMES)
            if not names or unknown:
                if reported:
                    found.append(Finding(path, ln, "allow-marker-invalid",
                                         "allow[...] must name detectors: "
                                         + (", ".join(unknown) or "(none)")))
                continue
            scope = names
        if not _marker_reason_ok(m.group("reason")):
            if reported:
                found.append(Finding(path, ln, "allow-marker-without-reason",
                                     "an allow marker must say why the value is safe"))
            continue
        allowed.setdefault(ln, []).append(_Allow(scope))
        # A marker alone on a comment line covers the next line. In a diff
        # the marker line must be part of the same change: an old marker does
        # not approve a later edit of the line below it.
        if _MARKER_ONLY_LINE.match(lines[ln - 1]) and (only_lines is None or ln in only_lines):
            allowed.setdefault(ln + 1, []).append(_Allow(scope))

    spans_by_line: dict[int, list[tuple[int, int]]] = {}
    every = hits + local_hits
    for h in every:
        ln = line_of(h.start)
        base = starts[ln - 1]
        end_in_line = min(h.end, base + len(lines[ln - 1]))
        spans_by_line.setdefault(ln, []).append((h.start - base, end_in_line - base))

    seen: set[tuple[int, str]] = set()
    for h in sorted(every, key=lambda x: x.start):
        ln = line_of(h.start)
        if only_lines is not None and ln not in only_lines:
            continue
        if any(a.covers(h.detector) for a in allowed.get(ln, ())):
            continue
        if (ln, h.detector) in seen:
            continue
        seen.add((ln, h.detector))
        column = h.start - starts[ln - 1]
        excerpt = _excerpt(lines[ln - 1], spans_by_line[ln], column)
        found.append(Finding(path, ln, h.detector, excerpt, column=column + 1))
    return found


def scan_blob(
    path: str,
    data: Optional[bytes],
    *,
    publish: bool,
    local: Optional[LocalBlock],
    only_lines: Optional[set[int]] = None,
) -> list[Finding]:
    found = path_findings(path, data, local, publish=publish)
    if data is None:
        return found
    decoded = None if _BINARY_EXT.search(path) else decode_text(data)
    if decoded is None:
        return found + _shown(binary_findings(path, data, publish=publish, local=local), path, local)
    if decoded[1] != "utf-8":
        only_lines = None  # diffed as binary: no line numbers, so scan all of it
    content = scan_text(path, decoded[0], publish=publish, local=local, only_lines=only_lines)
    return found + _shown(content, path, local)


# In binary content only shapes with a fixed, distinctive form are judged:
# the value heuristics (entropy, "looks real") misfire on compressed data and
# on compiled constants glued to their neighbours.
_BINARY_SHAPES = frozenset({
    "private-key", "age-secret-key", "putty-private-key", "aws-access-key-id", "github-token",
    "slack-token", "slack-webhook", "anthropic-key", "openai-style-key", "resend-key",
    "stripe-key", "google-api-key", "tailscale-key", "jwt", "fernet-token", "url-credentials",
    "webhook-signing-secret", "itglue-api-key", "telegram-bot-token", "cloudflare-tunnel-token",
    "fernet-or-base64-key",
})


def binary_findings(path: str, data: bytes, *, publish: bool,
                    local: Optional[LocalBlock]) -> list[Finding]:
    """Binary content: local-block terms and distinctive token shapes in its
    strings, and in --publish any binary type that is not an image or a font."""
    found: list[Finding] = []
    if publish and not _PUBLISH_BINARY_OK.search(path):
        found.append(Finding(path, 0, "binary-file",
                             "binary content cannot be checked for secrets or client names; only "
                             "images and fonts are committed or published: keep this file outside "
                             "the repository, or commit a text form of it"))
    strings = binary_strings(data)
    if not strings:
        return found
    if local is not None:
        m = local.search(strings)
        if m is not None:
            found.append(Finding(path, 0, "local-block",
                                 "binary content contains a local-block term: " + sp.mask(m.group(0))))
    seen: set[str] = set()
    # Only the fixed shapes are asked for, before overlaps are resolved: a
    # heuristic hit (entropy) never hides a token shape it overlaps.
    for h in sp.find_hits(strings, sp.Context(path=path), "scan", only=_BINARY_SHAPES):
        if h.detector in seen:
            continue
        seen.add(h.detector)
        found.append(Finding(path, 0, h.detector, "binary content: " + sp.mask(h.value)))
    return found


# --------------------------------------------------------------------------- #
# git plumbing
# --------------------------------------------------------------------------- #

class GitError(RuntimeError):
    pass


def _git(repo: Path, *args: str, check: bool = True, binary: bool = False, paths: bool = False):
    """git's output: bytes (``binary``), or text. ``paths``: the output names
    files (a path list, a patch's headers, a directory), decoded with
    surrogateescape so a name that is not UTF-8 maps back to its exact bytes
    (a U+FFFD in its place names no file git or the file system knows)."""
    proc = subprocess.run(
        ["git", "-c", "core.quotepath=off", "-C", str(repo), *args],
        capture_output=True,
    )
    if proc.returncode != 0:
        if check:
            raise GitError(printable(f"git {' '.join(args)}: "
                                     f"{proc.stderr.decode('utf-8', 'replace').strip()}"))
        return None
    if binary:
        return proc.stdout
    return proc.stdout.decode("utf-8", "surrogateescape" if paths else "replace")


class _BlobReader:
    """``git cat-file --batch``: one process for every blob in a run."""

    def __init__(self, repo: Path) -> None:
        self._proc = subprocess.Popen(
            ["git", "-C", str(repo), "cat-file", "--batch"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )

    def read(self, spec: str) -> Optional[bytes]:
        obj = self.read_object(spec)
        return obj[1] if obj is not None and obj[0] == "blob" else None

    def read_object(self, spec: str) -> Optional[tuple[str, bytes]]:
        """``(type, content)`` of any object, or None when it is missing."""
        assert self._proc.stdin and self._proc.stdout
        if "\n" in spec:
            return None
        self._proc.stdin.write(spec.encode() + b"\n")
        self._proc.stdin.flush()
        header = self._proc.stdout.readline().decode().split()
        if len(header) < 3 or header[1] == "missing":
            return None
        size = int(header[2])
        data = self._proc.stdout.read(size)
        self._proc.stdout.read(1)  # trailing newline
        return header[1], data

    def close(self) -> None:
        if self._proc.stdin:
            self._proc.stdin.close()
        self._proc.wait()


_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
# The patch format this parser reads, whatever the user's configuration says
# (diff.mnemonicPrefix / diff.noprefix / diff.srcPrefix change the a/ b/
# prefixes; diff.relative narrows the paths; a textconv driver rewrites the
# lines). Options win over configuration.
_PATCH_CONFIG = ("-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false",
                 "-c", "diff.relative=false", "-c", "color.diff=false")
_PATCH_OPTS = ("-U0", "--no-color", "--no-ext-diff", "--no-textconv", "--no-relative",
               "--src-prefix=a/", "--dst-prefix=b/")


_C_ESCAPE = re.compile(rb'\\(?:([0-7]{3})|(.))', re.S)
_C_ESCAPES = {b"a": b"\a", b"b": b"\b", b"t": b"\t", b"n": b"\n", b"v": b"\v", b"f": b"\f",
              b"r": b"\r", b'"': b'"', b"\\": b"\\"}


def _unquote(path: str) -> str:
    """Undo git's C-style quoting of a path with special characters, byte
    for byte (``\\t``, ``\\"``, ``\\303\\251``; with core.quotepath=off bytes
    over 0x7f come verbatim): the result is decoded like every other path
    (surrogateescape), so it names the same file as the ``-z`` lists."""
    if len(path) >= 2 and path[0] == '"' and path[-1] == '"':
        try:
            raw = path[1:-1].encode("utf-8", "surrogateescape")
        except UnicodeEncodeError:
            return path[1:-1]

        def unescape(m: "re.Match[bytes]") -> bytes:
            if m.group(1) is not None:
                return bytes([int(m.group(1), 8) & 0xFF])
            return _C_ESCAPES.get(m.group(2), m.group(0))

        return _C_ESCAPE.sub(unescape, raw).decode("utf-8", "surrogateescape")
    return path


def added_lines(diff: str) -> dict[str, set[int]]:
    """New-side line numbers of every ``+`` line, per file, from a -U0 diff.

    A hunk body is consumed by the line counts in its ``@@`` header, so an
    added line that itself starts with ``++ `` (shown as ``+++ ...``) is
    content, never a file header. A file that is missing from the result
    (a diff this parser could not read) is scanned whole by the callers."""
    out: dict[str, set[int]] = {}
    current: Optional[str] = None
    old_left = new_left = 0
    lineno = 0
    for line in diff.split("\n"):
        if old_left > 0 or new_left > 0:
            if line.startswith("+"):
                if current is not None:
                    out[current].add(lineno)
                lineno += 1
                new_left -= 1
                continue
            if line.startswith("-"):
                old_left -= 1
                continue
            if line.startswith(" "):
                lineno += 1
                old_left -= 1
                new_left -= 1
                continue
            if line.startswith("\\"):  # "\ No newline at end of file"
                continue
            old_left = new_left = 0  # a malformed hunk: back to headers
        if line.startswith("diff "):
            current = None
        elif line.startswith("+++ "):
            target = line[4:].rstrip("\t")
            current = None if target == "/dev/null" else _unquote(target)
            if current is not None:
                current = current[2:] if current.startswith("b/") else None
            if current is not None:
                out.setdefault(current, set())
        elif line.startswith("@@"):
            m = _HUNK.match(line)
            if m is None:
                continue
            old_left = int(m.group(2)) if m.group(2) is not None else 1
            new_left = int(m.group(4)) if m.group(4) is not None else 1
            lineno = int(m.group(3))
    return out


def _changed_paths(raw: str) -> list[str]:
    return [p for p in raw.split("\0") if p]


UNREADABLE = "unreadable-file"
_RAW_META = re.compile(r":([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}|[0-9a-f]{64}) ([0-9a-f]{40}|[0-9a-f]{64}) [A-Z][0-9]*")
_GITLINK = "160000"


def _changed_blobs(raw: str) -> list[tuple[str, str, str]]:
    """``(path, new mode, new object id)`` per change in ``--raw -z
    --no-abbrev --no-renames`` output (one ``:<modes> <ids> <status>``
    record, then its path). Anything else in it is an error, never a skipped
    file."""
    fields = raw.split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    if len(fields) % 2:
        raise GitError("git diff --raw: unexpected output (an odd number of fields)")
    out: list[tuple[str, str, str]] = []
    for meta, path in zip(fields[0::2], fields[1::2]):
        m = _RAW_META.fullmatch(meta.strip("\n"))
        if m is None or not path:
            raise GitError("git diff --raw: unexpected output (a record without its mode and ids)")
        out.append((path, m.group(2), m.group(4)))
    return out


def _unreadable(path: str, local: Optional[LocalBlock], what: str) -> list[Finding]:
    return _shown([Finding(path, 0, UNREADABLE, f"{what}: nothing in it was checked, so this is a "
                                                "refusal (fail closed)")], path, local)


def _scan_change(reader: _BlobReader, path: str, mode: str, obj: str, *, publish: bool, local,
                 only_lines: Optional[set[int]]) -> list[Finding]:
    """One added or changed file of a commit or of the index: its blob, read
    by object id (never by a path spec, which a name that is not UTF-8 would
    not survive). A gitlink is a commit of another repository: its name only.
    A blob that cannot be read is a finding: fail closed."""
    if mode == _GITLINK:
        return scan_blob(path, None, publish=publish, local=local)
    data = reader.read(obj) if obj.strip("0") else None
    if data is None:
        return (path_findings(path, None, local, publish=publish)
                + _unreadable(path, local, f"git could not produce this file's content (blob {obj[:12]})"))
    # A path the patch did not account for is scanned whole: fail closed.
    return scan_blob(path, data, publish=publish, local=local, only_lines=only_lines)


def scan_staged(repo: Path, *, publish: bool, local) -> list[Finding]:
    changes = _changed_blobs(_git(repo, "diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames",
                                  "--no-relative", "--no-ext-diff", "--diff-filter=ACMRT", paths=True))
    if not changes:
        return []
    lines = added_lines(_git(repo, *_PATCH_CONFIG, "diff", "--cached", *_PATCH_OPTS,
                             "--no-renames", "--diff-filter=ACMRT", paths=True))
    reader = _BlobReader(repo)
    try:
        found: list[Finding] = []
        for path, mode, obj in changes:
            found += _scan_change(reader, path, mode, obj, publish=publish, local=local,
                                  only_lines=lines.get(path))
        return found
    finally:
        reader.close()


def scan_message(label: str, text: str, *, publish: bool, local, commit: str = "") -> list[Finding]:
    """A commit or tag message: the same detectors and local-block terms."""
    return [replace(f, commit=commit) for f in scan_text(label, text, publish=publish, local=local)]


def scan_ref_name(name: str, *, local, publish: bool = False, label: str = REF_NAME,
                  what: str = "the ref name", hint: str = "") -> list[Finding]:
    """A ref name a push would create on the remote (``refs/heads/...``,
    ``refs/tags/...``), or the name an annotated tag object records: the
    remote shows it to everyone who can list refs / read the tag, so a
    local-block term or a secret shape in it is refused like one in a file,
    and with ``publish`` so is every publish-only value (an IP, an e-mail
    address, a home path, a ticket number, a tailnet name). A word-bounded
    term is also found where ``_`` or digits join it to the rest of the
    name. The name is printed masked, like a file name. Of the secret
    detectors only token shapes with a fixed, distinctive form are judged
    (as in binary content): the value heuristics (entropy, long hex) would
    refuse ordinary names such as a commit id. They are left out before
    overlaps are resolved (``find_hits(only=...)``), so one of them never
    hides an IP, a ticket number or an e-mail address it overlaps
    (``token=<ticket>``, ``password=<address>``)."""
    local_spans = _local_name_spans(name, local)
    judged = _BINARY_SHAPES | (sp.PUBLISH_ONLY_NAMES if publish else frozenset())
    hits = sp.find_hits(name, sp.Context(path=name), "scan", publish=publish, only=judged)
    shown = display_path(name, local, local_spans + [(h.start, h.end) for h in hits])
    found: list[Finding] = []
    if local_spans:
        found.append(Finding(label, 0, "local-block",
                             f"{what} contains a local-block term: {shown}{hint}"))
    seen: set[str] = set()
    for h in hits:
        if h.detector not in seen:
            seen.add(h.detector)
            found.append(Finding(label, 0, f"ref:{h.detector}",
                                 f"{what} contains {sp.mask(h.value)}: {shown}{hint}"))
    return found


_TAG_NAME_HINT = ("; the tag object records this name, whatever name it is pushed under: "
                  "re-create the tag under a neutral name")


def scan_tag_name(name: str, *, local, publish: bool = False) -> list[Finding]:
    """The ``tag <name>`` header of an annotated tag object being pushed."""
    return scan_ref_name(name, local=local, publish=publish, label=TAG_NAME,
                         what="the annotated tag's recorded name", hint=_TAG_NAME_HINT)


# git's own text in the editor template. With cleanup=strip (the default with
# an editor) it says comment lines will be ignored; with cleanup=whitespace or
# verbatim that they will be kept. Each names the comment string, and git
# writes it as the second line of its comment block, right under
# "<c> Please enter the commit message for your changes. Lines starting".
_STRIP_HINT_TEXT = "will be ignored, and an empty message aborts the commit."
_KEEP_HINT_TEXT = "will be kept; you may remove them yourself if you want to."
_STRIP_HINT_LEAD = "Please enter the commit message for your changes. Lines starting"
#: What core.commentChar=auto picks from (git's candidates).
_AUTO_COMMENT_CHARS = "#;@!$%^&|:"


@dataclass(frozen=True)
class MessageConfig:
    """What git's configuration says about the message a commit keeps: the
    comment strings git may use (the configured one, or git's candidates for
    ``auto``) and commit.cleanup (lower case, "" when unset)."""

    comments: tuple[str, ...] = ("#",)
    cleanup: str = ""


def _git_version(repo: Path) -> tuple[int, int]:
    m = re.search(r"(\d+)\.(\d+)", _git(repo, "version", check=False) or "")
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def message_config(repo: Path) -> MessageConfig:
    """git's comment string and cleanup mode for a commit in ``repo``:
    core.commentChar, or core.commentString (git 2.45+, where the two are
    one setting and the last one set wins), ``#`` when neither is set, every
    candidate character for ``auto``; and commit.cleanup. ``git -c ...``
    reaches the hook too (it inherits git's environment); a ``--cleanup=``
    option does not (see message_file_text)."""
    out = _git(repo, "config", "-z", "--get-regexp", r"^core\.comment(char|string)$", check=False) or ""
    both = _git_version(repo) >= (2, 45)
    value: Optional[str] = None
    for record in out.split("\0"):
        key, _, val = record.partition("\n")
        if key == "core.commentchar" or (both and key == "core.commentstring"):
            value = val
    if not value:
        comments: tuple[str, ...] = ("#",)
    elif value.lower() == "auto":
        comments = tuple(_AUTO_COMMENT_CHARS)
    else:
        comments = (value,)
    cleanup = (_git(repo, "config", "--get", "commit.cleanup", check=False) or "").strip().lower()
    return MessageConfig(comments, cleanup)


@functools.lru_cache(maxsize=32)
def _message_patterns(comments: tuple[str, ...]) -> tuple["re.Pattern[str]", "re.Pattern[str]", "re.Pattern[str]"]:
    """(scissors block, strip hint, keep hint) on these comment strings."""
    alt = "|".join(re.escape(c) for c in sorted(set(comments), key=len, reverse=True))
    # The scissors block exactly as git writes it (wt_status_add_cut_line):
    # the cut line and its two explanation lines, all three on one comment
    # string. A scissors line alone may have been typed: git cuts at one only
    # with -v or cleanup=scissors, and keeps what follows otherwise.
    scissors = re.compile(
        rf"^(?P<c>{alt}) -{{24}} >8 -{{24}}\r?\n"
        r"(?P=c) Do not modify or remove the line above\.\r?\n"
        r"(?P=c) Everything below it will be ignored\.\r?$", re.M
    )
    strip = re.compile(rf"^(?P<c>{alt}) with '(?P=c)' {re.escape(_STRIP_HINT_TEXT)}\r?$", re.M)
    keep = re.compile(rf"^(?P<c>{alt}) with '(?P=c)' {re.escape(_KEEP_HINT_TEXT)}\r?$", re.M)
    return scissors, strip, keep


def message_file_text(raw: str, *, editor: bool = True, config: MessageConfig = MessageConfig()) -> str:
    """What a commit message file will become, as far as the hook can tell.

    git keeps comment lines with ``git commit -m`` / ``-F``
    (cleanup=whitespace) and with cleanup=verbatim, so they are checked like
    any other line. They are dropped only when an editor ran (``editor``:
    the hook's ``GIT_EDITOR`` is not ``:``) and git's own template says it
    strips them (its "will be ignored" hint), and never with
    commit.cleanup=whitespace / verbatim / scissors in git's configuration.
    The comment string is git's (``config``, from core.commentChar /
    core.commentString: ``#`` by default), never one the text names: a hint
    or a block on another string is just text.

    The ``git commit -v`` scissors block and everything below it are cut,
    but only when an editor ran and the block is git's own: the exact cut
    line followed by git's two explanation lines (``Do not modify or remove
    the line above.`` / ``Everything below it will be ignored.``), followed
    in turn by git's -v diff (``diff --git``, after comment and blank lines
    only). With commit.cleanup=scissors configured, a block that only
    comment and blank lines follow cuts too (git truncates there). A block
    followed by anything else, or by comment lines alone under any other
    cleanup (cleanup=whitespace keeps them; cleanup=strip drops them anyway
    when its hint is there), is not honoured. Without an editor git writes
    no scissors line, and one typed into the message is kept by git unless
    -v or cleanup=scissors is used, so it is not honoured (the pre-push hook
    checks what was stored anyway). git writes those lines in the user's
    language: with a translated git the diff below them is checked too
    (refused only if it carries a finding; commit without -v, or with
    LC_ALL=C).

    Text typed or pasted into the message is not trusted as git's: only the
    LAST "will be ignored" hint counts, only where git writes it (right
    under ``<c> Please enter the commit message for your changes. Lines
    starting``), and not at all when git's "will be kept" hint is there too
    (git writes one hint: that one says a ``--cleanup=whitespace`` /
    ``verbatim`` option is in effect). A ``--cleanup=`` option without its
    hint (``--no-status``) is not visible to the hook: the pre-push hook
    checks what was stored."""
    if not editor:
        return raw
    comments = config.comments or ("#",)
    cut = _scissors_cut(raw, comments, comment_tail=config.cleanup == "scissors")
    if cut is not None:
        raw = raw[:cut]
    if config.cleanup in ("whitespace", "verbatim", "scissors"):
        return raw  # git keeps every comment line (scissors: those above the cut)
    comment = _strip_comment(raw, comments)
    if comment is None:
        return raw
    return "\n".join("" if line.startswith(comment) else line for line in raw.split("\n"))


def _scissors_cut(raw: str, comments: tuple[str, ...] = ("#",), *, comment_tail: bool = False) -> Optional[int]:
    """Where git cuts the message: the first of git's scissors blocks (see
    _message_patterns) that git's -v diff follows (after comment and blank
    lines only), or, with ``comment_tail`` (commit.cleanup=scissors), that
    nothing but comment and blank lines follow. Each block looks forward to
    the next line that is neither (O(distance)), and a block before that
    line reuses the answer: a message of many pasted blocks stays linear."""
    scissors = _message_patterns(tuple(comments))[0]
    content: dict[str, "re.Pattern[str]"] = {}
    known: dict[str, int] = {}  # comment string -> start of the next content line (-1: none)
    for m in scissors.finditer(raw):
        c = m.group("c")
        nxt = known.get(c)
        if nxt is None or (nxt != -1 and nxt < m.end()):
            rx = content.get(c)
            if rx is None:
                # A line that is neither blank nor a comment on this string.
                rx = content[c] = re.compile(rf"^(?!{re.escape(c)})(?![^\S\n]*$)", re.M)
            found = rx.search(raw, m.end())  # m.end() is mid-line: the block's own line is skipped
            nxt = known[c] = found.start() if found else -1
        if nxt == -1:
            return m.start() if comment_tail else None  # and so for every later block
        if raw.startswith("diff --git ", nxt):
            return m.start()
    return None


def _under_lead(raw: str, hint: "re.Match[str]") -> bool:
    """A hint sits where git writes it: right under its lead line, on the
    same comment string."""
    above_end = hint.start() - 1  # the "\n" that ends the line above
    if above_end < 0:
        return False
    above = raw[raw.rfind("\n", 0, above_end) + 1:above_end].rstrip("\r")
    return above == f"{hint.group('c')} {_STRIP_HINT_LEAD}"


def _strip_comment(raw: str, comments: tuple[str, ...] = ("#",)) -> Optional[str]:
    """The comment string git strips, named by the LAST strip hint in
    ``raw`` (on one of ``comments``), if that hint sits where git writes it
    and no keep hint of git's is there; else None: nothing is stripped."""
    _, strip, keep = _message_patterns(tuple(comments))
    hint = None
    for hint in strip.finditer(raw):
        pass
    if hint is None or not _under_lead(raw, hint):
        return None
    if any(_under_lead(raw, k) for k in keep.finditer(raw)):
        return None
    return hint.group("c")


def _known_on_remote(repo: Path, remote: Optional[str]) -> list[str]:
    """``rev-list`` arguments that leave out what this clone's remote-tracking
    refs say a remote holds: ``--remotes=<name>`` for a configured remote,
    every remote-tracking ref for None, nothing at all for anything else (a
    URL: nothing is known to be there, so everything is checked). Tracking
    refs can be stale (a branch deleted or force-pushed away elsewhere stays
    until ``fetch --prune``): the pre-push hook asks the remote itself
    instead (``--remote-tips``)."""
    if remote is None:
        return ["--not", "--remotes"]
    if remote in (_git(repo, "remote") or "").split():
        return ["--not", f"--remotes={remote}"]
    return []


_OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def remote_tips(repo: Path, listing: str) -> list[str]:
    """The commits a remote holds that this clone has too, from ``git
    ls-remote`` output (or one object id per line): each id peeled to a
    commit; ids this clone does not have, or that name no commit, are left
    out (what they reach is then checked, never assumed present)."""
    ids = sorted({f[0] for f in (line.split() for line in listing.splitlines())
                  if f and _OBJECT_ID.fullmatch(f[0])})
    if not ids:
        return []
    proc = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "--batch-check=%(objectname) %(objecttype)"],
        input="".join(f"{i}^{{commit}}\n" for i in ids).encode(), capture_output=True,
    )
    if proc.returncode != 0:
        raise GitError("git cat-file --batch-check: " + proc.stderr.decode("utf-8", "replace").strip())
    tips: set[str] = set()
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        sha, _, kind = line.partition(" ")
        if kind == "commit" and _OBJECT_ID.fullmatch(sha):
            tips.add(sha)
    return sorted(tips)


def _rev_list(repo: Path, spec: str, exclude: list[str]) -> Optional[list[str]]:
    """``git rev-list --reverse <spec> ^<each of exclude>`` (the exclusions
    on stdin: a remote may have thousands of refs); None when git fails."""
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-list", "--reverse", "--stdin", spec, "--"],
        input="".join(f"^{t}\n" for t in exclude).encode(), capture_output=True,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", "replace").split()


def commits_in(repo: Path, spec: str, remote: Optional[str],
               tips: Optional[list[str]] = None) -> list[str]:
    """The commits ``--range`` checks.

    With ``tips`` (``--remote-tips``: what the remote holds, as the pre-push
    hook just listed it), every commit reachable from one of them is left
    out: moving ``main`` to commits pushed on another branch sends nothing
    new, while a commit the remote no longer holds (its branch deleted or
    force-pushed away) is checked again. An empty list: the remote holds
    nothing known, so ``A..B`` is exactly that range and a single rev is its
    whole history.

    Without tips, ``A..B`` with ``--remote`` leaves out what the clone's
    remote-tracking refs for it say (possibly stale); ``A..B`` alone is
    exactly that range; a single rev is every commit not on the remote (any
    remote when none is named)."""
    if tips is not None:
        if ".." in spec:
            out = _rev_list(repo, spec, tips)
            if out is not None:
                return out
            spec = spec.split("..", 1)[1] or "HEAD"  # unknown base (e.g. after a force-push)
        out = _rev_list(repo, spec, tips)
        if out is None:
            raise GitError(f"git rev-list {spec}: not a revision this clone has")
        return out
    if ".." in spec:
        known = _known_on_remote(repo, remote) if remote is not None else []
        out = _git(repo, "rev-list", "--reverse", spec, *known, check=False)
        if out is not None:
            return out.split()
        spec = spec.split("..", 1)[1] or "HEAD"  # unknown base (e.g. after a force-push)
    return _git(repo, "rev-list", "--reverse", spec, *_known_on_remote(repo, remote)).split()


def _commit_messages(repo: Path, shas: list[str]) -> dict[str, str]:
    if not shas:
        return {}
    proc = subprocess.run(
        ["git", "-C", str(repo), "log", "--no-walk=unsorted", "--no-show-signature", "--stdin", "-z",
         "--format=%H%n%B"],
        input="\n".join(shas).encode(), capture_output=True,
    )
    if proc.returncode != 0:
        raise GitError("git log: " + proc.stderr.decode("utf-8", "replace").strip())
    out: dict[str, str] = {}
    for record in proc.stdout.decode("utf-8", "replace").split("\0"):
        sha, _, body = record.lstrip("\n").partition("\n")
        if sha:
            out[sha] = body
    return out


_TAG_HEADER_NAME = re.compile(r"^tag (.*)$", re.M)


def _annotated_tags(repo: Path, spec: str) -> list[tuple[str, str, str]]:
    """``(tag object, recorded name, message)`` for an annotated tag at the
    tip of ``spec`` (nested tags followed). The name is the object's own
    ``tag <name>`` header: it travels with the object, so a tag pushed under
    a neutral ref name still carries it."""
    obj = spec.split("..", 1)[1] if ".." in spec else spec
    found: list[tuple[str, str, str]] = []
    for _ in range(8):
        if (_git(repo, "cat-file", "-t", obj, check=False) or "").strip() != "tag":
            break
        raw = _git(repo, "cat-file", "tag", obj)
        header, _, message = raw.partition("\n\n")
        name = _TAG_HEADER_NAME.search(header)
        found.append((obj, name.group(1) if name else "", message))
        m = re.match(r"object ([0-9a-f]+)", header)
        if m is None:
            break
        obj = m.group(1)
    return found


def scan_range(repo: Path, spec: str, remote: Optional[str], *, publish: bool, local,
               tips: Optional[list[str]] = None) -> list[Finding]:
    reader = _BlobReader(repo)
    found: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    def add(f: Finding, sha: str) -> None:
        key = (f.path, f.detector, f.excerpt)
        if key not in seen:
            seen.add(key)
            found.append(replace(f, commit=sha))

    try:
        for tag, name, message in _annotated_tags(repo, spec):
            for f in scan_tag_name(name, local=local, publish=publish):
                add(f, tag)
            for f in scan_message(TAG_MESSAGE, message, publish=publish, local=local):
                add(f, tag)
        shas = commits_in(repo, spec, remote, tips)
        messages = _commit_messages(repo, shas)
        for sha in shas:
            for f in scan_message(COMMIT_MESSAGE, messages.get(sha, ""), publish=publish, local=local):
                add(f, sha)
            common = ["--no-commit-id", "-r", "--root", "--no-renames", "--diff-filter=ACMRT",
                      "--diff-merges=first-parent"]
            changes = _changed_blobs(_git(repo, "diff-tree", "--raw", "-z", "--no-abbrev", *common, sha,
                                          paths=True))
            if not changes:
                continue
            lines = added_lines(_git(repo, *_PATCH_CONFIG, "diff-tree", "-p", *_PATCH_OPTS,
                                     *common, sha, paths=True))
            for path, mode, obj in changes:
                for f in _scan_change(reader, path, mode, obj, publish=publish, local=local,
                                      only_lines=lines.get(path)):
                    add(f, sha)
        return found
    finally:
        reader.close()


# --------------------------------------------------------------------------- #
# Every object the repository holds (--all-history)
# --------------------------------------------------------------------------- #

def _object_types(repo: Path, shas: list[str]) -> dict[str, str]:
    """``git cat-file --batch-check``: object id -> type (missing ones left out)."""
    if not shas:
        return {}
    proc = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "--batch-check=%(objectname) %(objecttype)"],
        input=("\n".join(shas) + "\n").encode(), capture_output=True,
    )
    if proc.returncode != 0:
        raise GitError("git cat-file --batch-check: " + proc.stderr.decode("utf-8", "replace").strip())
    out: dict[str, str] = {}
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        sha, _, kind = line.partition(" ")
        if kind and kind != "missing":
            out[sha] = kind
    return out


_OBJECT_LINE = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})(?: (.*))?$")


def _reachable_objects(repo: Path) -> dict[str, str]:
    """Object id -> the path ``rev-list`` names it by ("" for commits, tags
    and root trees): everything reachable from a ref, a reflog entry (stashes
    included) or an index, in every worktree."""
    out = _git(repo, "rev-list", "--objects", "--all", "--reflog", "--indexed-objects")
    objects: dict[str, str] = {}
    for line in out.split("\n"):
        m = _OBJECT_LINE.match(line)
        if m is not None:
            objects.setdefault(m.group(1), m.group(2) or "")
    return objects


def _unreachable_objects(repo: Path) -> dict[str, str]:
    """Object id -> type for every object no ref, index or HEAD reaches
    (reflog-only objects included: ``rev-list --reflog`` lists those too)."""
    proc = subprocess.run(
        ["git", "-C", str(repo), "fsck", "--unreachable", "--no-reflogs", "--connectivity-only",
         "--no-progress"],
        capture_output=True,
    )
    if proc.returncode != 0:  # a broken object store: the scan would be partial
        raise GitError("git fsck: " + proc.stderr.decode("utf-8", "replace").strip())
    found: dict[str, str] = {}
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] in ("unreachable", "dangling"):
            found[parts[2]] = parts[1]
    return found


def _tree_entries(data: bytes, hash_len: int) -> Iterator[tuple[str, str, str]]:
    """``(mode, name, object id)`` for each entry of a raw tree object."""
    pos = 0
    while pos < len(data):
        space = data.find(b" ", pos)
        nul = data.find(b"\0", space + 1) if space != -1 else -1
        if nul == -1:
            return
        yield (data[pos:space].decode("ascii", "replace"), data[space + 1:nul].decode("utf-8", "replace"),
               data[nul + 1:nul + 1 + hash_len].hex())
        pos = nul + 1 + hash_len


def _unreachable_paths(reader: _BlobReader, unreachable: dict[str, str],
                       hash_len: int) -> tuple[dict[str, set[str]], set[str]]:
    """Blob id -> every path an unreachable tree gives it: the full path
    under an unreachable commit (a dropped stash, an amended commit), else
    the path relative to a dangling tree (``git write-tree`` output nothing
    kept). Reachable trees are not walked: every blob in them is reachable.
    Also every name those trees carry (a directory, a submodule, a
    reachable subtree under a new name): file names are checked like
    contents."""
    trees = {sha for sha, kind in unreachable.items() if kind == "tree"}
    entries: dict[str, list[tuple[str, str, str]]] = {}

    def children(tree: str) -> list[tuple[str, str, str]]:
        if tree not in entries:
            obj = reader.read_object(tree)
            entries[tree] = list(_tree_entries(obj[1], hash_len)) if obj and obj[0] == "tree" else []
        return entries[tree]

    paths: dict[str, set[str]] = {}
    names: set[str] = set()
    visited: set[str] = set()
    walked: set[tuple[str, str]] = set()

    def walk(root: str) -> None:
        stack = [(root, "")]
        while stack:
            tree, prefix = stack.pop()
            if (tree, prefix) in walked:  # the same tree under another name: walked again
                continue
            walked.add((tree, prefix))
            visited.add(tree)
            for mode, name, sha in children(tree):
                path = prefix + name
                names.add(path)
                if mode.startswith("4"):  # 40000: a subtree
                    if sha in trees:
                        stack.append((sha, path + "/"))
                elif mode != "160000":  # a gitlink names a commit of another repo
                    paths.setdefault(sha, set()).add(path)

    for sha, kind in sorted(unreachable.items()):
        if kind != "commit":
            continue
        obj = reader.read_object(sha)
        m = re.match(rb"tree ([0-9a-f]+)", obj[1]) if obj else None
        if m is not None and m.group(1).decode() in trees:
            walk(m.group(1).decode())
    under = {sha for tree in trees for mode, _, sha in children(tree) if mode.startswith("4")}
    for tree in sorted(trees - under - visited):
        walk(tree)
    return paths, names


def _historical_paths(repo: Path) -> tuple[dict[str, set[str]], set[str]]:
    """``(blob id -> every path a commit gave it, every path)``: what each
    reachable commit (or reflog entry) added, changed or deleted, from
    ``git log --raw`` (one ``:<modes> <old> <new> <status>`` record and its
    path per change)."""
    out = _git(repo, "log", "--all", "--reflog", "--format=", "--raw", "--no-abbrev", "-z",
               "--no-renames", "--diff-merges=first-parent", check=False)
    by_blob: dict[str, set[str]] = {}
    names: set[str] = set()
    fields = (out or "").split("\0")
    i = 0
    while i < len(fields):
        meta = fields[i].strip("\n")
        i += 1
        if not meta.startswith(":"):
            continue
        if i >= len(fields):
            break
        path = fields[i].strip("\n")
        i += 1
        if not path:
            continue
        names.add(path)
        parts = meta[1:].split()
        # :<old mode> <new mode> <old id> <new id> <status>; a gitlink (160000)
        # names a commit of another repository, a deletion no blob at all.
        if len(parts) >= 5 and parts[1] not in ("000000", "160000") and parts[3].strip("0"):
            by_blob.setdefault(parts[3], set()).add(path)
    return by_blob, names


def _strictness(path: str) -> tuple[int, str]:
    """Sort key for the names of one blob, strictest rules first: a normal
    name gets every detector; a lockfile skips e-mail addresses; a generated
    name (lockfiles, minified bundles, source maps) skips the entropy and
    32-byte-key rules; a binary extension gets only the strings of the
    content. Ties go to the name that sorts first."""
    if _BINARY_EXT.search(path):
        rank = 3
    elif _GENERATED.search(path):
        rank = 2
    elif sp.LOCKFILE.search(path):
        rank = 1
    else:
        rank = 0
    return rank, path


def scan_all_history(repo: Path, *, publish: bool, local) -> list[Finding]:
    """Every blob, commit message, annotated tag and file name the object
    store holds, reachable or not (see the module docstring)."""
    reachable = _reachable_objects(repo)
    unreachable = _unreachable_objects(repo)
    types = _object_types(repo, sorted(set(reachable) - set(unreachable)))
    types.update(unreachable)
    hash_len = 32 if (_git(repo, "rev-parse", "--show-object-format", check=False) or "").strip() == "sha256" \
        else 20
    reader = _BlobReader(repo)
    found: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    def add(f: Finding, obj: str) -> None:
        key = (f.path, f.detector, f.excerpt)
        if key not in seen:
            seen.add(key)
            found.append(replace(f, commit=obj))

    try:
        lost_paths, lost_names = _unreachable_paths(reader, unreachable, hash_len)
        committed, history_names = _historical_paths(repo)
        # Every name each blob was ever given; it is scanned under the one
        # with the strictest rules (a source name beats a lockfile, a
        # generated or a binary-extension name), and every other name is
        # checked as a file name of that content.
        blobs: dict[str, list[str]] = {}
        for sha, kind in sorted(types.items()):
            if kind != "blob":
                continue
            names_of = set(committed.get(sha, ())) | lost_paths.get(sha, set())
            if reachable.get(sha):
                names_of.add(reachable[sha])
            blobs[sha] = sorted(names_of, key=_strictness) or [f"{UNREACHABLE}/{sha[:12]}"]
        commits = sorted(sha for sha, kind in types.items() if kind == "commit")
        tags = sorted(sha for sha, kind in types.items() if kind == "tag")
        print(f"scan-sensitive: --all-history: {len(blobs)} blob(s), {len(commits)} commit(s), "
              f"{len(tags)} annotated tag(s); {len(unreachable)} unreachable object(s)",
              file=sys.stderr)

        for sha, text in _commit_messages(repo, commits).items():
            for f in scan_message(COMMIT_MESSAGE, text, publish=publish, local=local):
                add(f, sha)
        for sha in tags:
            obj = reader.read_object(sha)
            if obj is None:
                continue
            header, _, message = obj[1].decode("utf-8", "replace").partition("\n\n")
            name = _TAG_HEADER_NAME.search(header)
            for f in scan_tag_name(name.group(1) if name else "", local=local, publish=publish):
                add(f, sha)
            for f in scan_message(TAG_MESSAGE, message, publish=publish, local=local):
                add(f, sha)

        scanned_names: set[str] = set()
        for sha, paths in sorted(blobs.items(), key=lambda kv: (kv[1][0], kv[0])):
            data = reader.read(sha)
            scanned_names.update(paths)
            for f in scan_blob(paths[0], data, publish=publish, local=local):
                add(f, sha)
            for other in paths[1:]:  # the same content under another name (.env checks included)
                for f in path_findings(other, data, local, publish=publish):
                    add(f, sha)
        # A name with no blob behind it (a directory, a submodule, a deletion).
        names = (history_names | {p for p in reachable.values() if p} | lost_names) - scanned_names
        for path in sorted(names):
            for f in path_findings(path, None, local, publish=publish):
                add(f, "")
        return found
    finally:
        reader.close()


# A directory outside git (an export) is scanned as `git add -A` would
# commit it: every file, except the heavy generated directories below when
# the tree's own top-level .gitignore ignores the name at every depth (the
# way `git ls-files --others --exclude-standard` leaves them out) and no
# .gitignore on the way down re-includes it. Without such a line nothing is
# skipped: whatever is in the tree is what would be committed.
_WALK_SKIP = {".git"}
_WALK_IGNORABLE = frozenset({
    "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
})


def _gitignore_patterns(path: Path) -> list[str]:
    """The pattern lines of one .gitignore, cut as git cuts them: lines end
    at LF (a CR before it dropped) and only trailing SPACES are trimmed (a
    trailing tab is part of the pattern). None when it is not a regular file
    (a FIFO is never opened) or cannot be read."""
    try:
        if not path.is_file():
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = ((line[:-1] if line.endswith("\r") else line).rstrip(" ") for line in text.split("\n"))
    return [line for line in lines if line and not line.startswith("#")]


def _ignored_everywhere(patterns: list[str]) -> set[str]:
    """The _WALK_IGNORABLE names ignored at any depth: a line `name`,
    `name/`, `**/name` or `**/name/` (anchored or deeper patterns are not
    taken, so those directories are walked)."""
    names = set()
    for line in patterns:
        bare = line[3:] if line.startswith("**/") else line
        bare = bare[:-1] if bare.endswith("/") else bare
        if bare in _WALK_IGNORABLE:
            names.add(bare)
    return names


def _reincluded(patterns: list[str]) -> set[str]:
    """The _WALK_IGNORABLE names a `!` line could bring back (any of its
    path components, globs included, matches the name): git may list such
    a directory after all, so it is walked."""
    names = set()
    for line in patterns:
        if line.startswith("!"):
            for part in line[1:].strip("/").split("/"):
                if part:
                    names.update(n for n in _WALK_IGNORABLE if fnmatch.fnmatchcase(n, part))
    return names


def tree_files(root: Path, *, use_git: bool) -> Iterator[str]:
    """Every file of the tree: git's list (tracked and untracked, not
    ignored; names kept byte for byte), or, outside git, every file under
    ``root`` but the generated directories its .gitignore leaves out of a
    commit (see _WALK_IGNORABLE)."""
    if use_git:
        out = _git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard", check=False,
                   paths=True)
        if out is not None:
            for rel in sorted(set(_changed_paths(out))):
                yield rel
            return
    # git does not follow a .gitignore that is a symbolic link (it commits
    # what such a file names), so one at the top skips nothing. Deeper ones
    # only ever re-include, so reading them through a link walks more.
    top_ignore = root / ".gitignore"
    top = [] if top_ignore.is_symlink() else _gitignore_patterns(top_ignore)
    skip_in = {os.fspath(root): _ignored_everywhere(top) - _reincluded(top)}
    for dirpath, dirnames, filenames in os.walk(root):
        skip = skip_in.pop(dirpath, set())
        if skip and ".gitignore" in filenames:
            skip = skip - _reincluded(_gitignore_patterns(Path(dirpath) / ".gitignore"))
        dirnames[:] = sorted(d for d in dirnames if d not in _WALK_SKIP and d not in skip)
        for d in dirnames:
            skip_in[os.path.join(dirpath, d)] = skip
        for name in sorted(filenames):
            yield os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/")


def _deleted_files(root: Path) -> set[str]:
    """Tracked files missing from the work tree (``rm`` before ``git rm``):
    nothing there to check."""
    out = _git(root, "ls-files", "-z", "--deleted", check=False, paths=True)
    return set(_changed_paths(out)) if out else set()


def scan_tree(root: Path, *, publish: bool, local, use_git: bool) -> list[Finding]:
    """Every file of the tree (tree_files). A listed file that is gone
    without git knowing it was deleted, or that cannot be read, is a finding:
    fail closed. Symbolic links, directories (a submodule) and other
    non-files are not content."""
    found: list[Finding] = []
    deleted: Optional[set[str]] = None
    for rel in tree_files(root, use_git=use_git):
        full = root / rel
        if full.is_symlink() or full.is_dir():
            continue
        if not full.exists():
            if deleted is None:
                deleted = _deleted_files(root) if use_git else set()
            if rel not in deleted:
                found += _unreadable(rel, local, "listed, but not found in the work tree")
            continue
        if not full.is_file():
            continue  # a FIFO or a socket: no content to commit
        try:
            data = full.read_bytes()
        except OSError as exc:
            found += _unreadable(rel, local, f"could not be read ({type(exc).__name__})")
            continue
        found += scan_blob(rel, data, publish=publish, local=local)
    return found


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _toplevel(start: Path) -> Optional[Path]:
    out = _git(start, "rev-parse", "--show-toplevel", check=False, paths=True)
    return Path(out.strip()) if out else None


def _report(findings: list[Finding], quiet: bool) -> None:
    if not quiet:
        for f in sorted(findings, key=lambda x: (x.path, x.line, x.detector, x.commit)):
            print(f.render())
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.detector] = counts.get(f.detector, 0) + 1
    files = len({f.path for f in findings})
    print(f"\nscan-sensitive: {len(findings)} finding(s) in {files} file(s)")
    for name, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {n:5d}  {name}")
    print(_advice(set(counts)))


def _base_detector(name: str) -> str:
    """``path:ip-private`` / ``ref:email-address`` -> the detector name."""
    head, _, rest = name.partition(":")
    return rest if head in ("path", "ref") and rest else name


def _advice(detectors: set[str]) -> str:
    """What to do about the findings, by kind: secrets, never-public
    (publish-only) values, local-block terms."""
    bases = {_base_detector(d) for d in detectors}
    publish = sorted(b for b in bases if b in sp.PUBLISH_ONLY_NAMES)
    binary = "binary-file" in bases
    local = "local-block" in bases
    markers = {b for b in bases if b.startswith("allow-marker")}
    files = {b for b in bases if b.startswith("forbidden-file:")}
    unreadable = UNREADABLE in bases
    secret = bases - set(publish) - {"binary-file", "local-block", UNREADABLE} - markers - files
    out: list[str] = []
    if unreadable:
        out.append("A file whose content could not be read was not checked: fix what keeps it from\n"
                   "being read (a missing object: git fetch / git fsck; permissions), then run again.")
    if files:
        out.append("A never-commit file (a key, a vault, an .env with values, a database, a backup):\n"
                   "take it out of the commit; an .env.example with placeholders is fine.")
    if markers:
        out.append("An allow marker must give a reason and name real detectors\n"
                   "(scripts/scan_sensitive.py --list-detectors).")
    if secret:
        out.append(
            "A real secret: remove it, and treat it as exposed if it ever left this machine\n"
            "(SECURITY.md). A test value: generate it at runtime, or put an allow marker with\n"
            "a reason on that line.")
    if publish:
        example = publish[0]
        out.append(
            f"Never-public value(s) ({', '.join(publish)}): not secrets, but the public\n"
            "standard keeps them out of every file, file name, commit message and ref name,\n"
            "in the private repo too (SECURITY.md). Use a documentation value: an IP in\n"
            "192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24, an example.com address,\n"
            "/home/<user>, the ticket number T20000101.0001. If the value must stay, name the\n"
            f"detector in a marker with a reason: '# {sp.ALLOW_MARKER}[{example}] <why it is safe>'.\n"
            "A bare allow covers the secret detectors only. A file or ref name: rename it.\n"
            "A commit message: reword it (git commit --amend) before the push.")
    if binary:
        out.append(
            "A binary file that is not an image or a font cannot be checked for secrets or client\n"
            "names: keep it outside the repository, or commit a text form of it.")
    if local:
        out.append("A local-block term cannot be allowed inline: neutralize it.")
    return "\n" + "\n".join(out)


def main(argv: Optional[Iterable[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="scan_sensitive.py",
        description="Find secrets, never-commit files and never-public strings. Exit 1 on any hit.",
    )
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true", help="lines added in the index")
    mode.add_argument("--message", type=Path, metavar="FILE",
                      help="a commit message file (the commit-msg hook)")
    mode.add_argument("--range", dest="range_spec", metavar="A..B|REV",
                      help="every commit in A..B; REV alone = not yet on the remote")
    mode.add_argument("--tree", action="store_true", help="the working tree")
    mode.add_argument("--ref-name", dest="ref_names", action="append", metavar="NAME",
                      help="a ref name a push would create on the remote (repeatable)")
    mode.add_argument("--all-history", action="store_true",
                      help="every blob, commit / tag message and file name in the object store: "
                           "all refs, reflogs, indexes and unreachable objects (read-only)")
    ap.add_argument("--publish", action="store_true",
                    help="strictest: also IPs, home paths, memory links and memory-store paths, "
                         "tailnet names, e-mails, NextDNS profile ids, URL path tokens, ticket numbers "
                         "(what the hooks run)")
    ap.add_argument("--root", type=Path, help="directory for --tree / --publish (default: the repo)")
    ap.add_argument("--repo", type=Path, default=None, help="git repo for --staged / --range")
    ap.add_argument("--remote", help="with --range: skip commits this clone's remote-tracking refs "
                                     "say the remote has under any ref (a URL: none known; can be "
                                     "stale, see --remote-tips)")
    ap.add_argument("--remote-tips", type=Path, metavar="FILE",
                    help="with --range: skip commits reachable from these remote tips ('git ls-remote' "
                         "output or one id per line; empty = the remote holds nothing): what the "
                         "pre-push hook passes")
    ap.add_argument("--local-block", type=Path,
                    help=f"sensitive-terms file (default ${LOCAL_BLOCK_ENV}, else {LOCAL_BLOCK_REL})")
    ap.add_argument("--no-local-block", action="store_true", help="ignore the local-block file")
    ap.add_argument("-q", "--quiet", action="store_true", help="summary only")
    ap.add_argument("--list-detectors", action="store_true")
    ap.add_argument("--version", action="version", version=f"scan_sensitive {GUARDRAILS_VERSION}")
    args = ap.parse_args(list(argv) if argv is not None else None)

    if args.list_detectors:
        for name in sorted(sp.REPORTED_NAMES):
            print(f"{name} (--publish)" if name in sp.PUBLISH_ONLY_NAMES else name)
        for name, _ in _NEVER:
            print(f"forbidden-file:{name}")
        print(f"forbidden-file:env-with-values\nbinary-file (--publish)\n{UNREADABLE}\nlocal-block\n"
              "allow-marker-without-reason\nallow-marker-invalid\n"
              "path:<detector> (a detector hit in a file name)\n"
              "ref:<detector> (a detector hit in a pushed ref name or an annotated tag's name)\n"
              "allow[...] takes the bare names above (without ' (--publish)'); a bare allow "
              "covers the secret detectors only")
        return 0
    if not (args.staged or args.message or args.range_spec or args.ref_names
            or args.tree or args.all_history or args.publish):
        ap.error("choose --staged, --message, --range, --ref-name, --tree, --all-history or --publish")
    if (args.remote or args.remote_tips) and not args.range_spec:
        ap.error("--remote and --remote-tips go with --range")
    if args.remote and args.remote_tips:
        ap.error("--remote and --remote-tips are alternatives: the tips are what the remote holds")

    cwd = Path.cwd()
    repo = (args.repo or _toplevel(cwd) or cwd).resolve()
    local = None
    if not args.no_local_block:
        if args.local_block is not None:
            lb_path: Optional[Path] = args.local_block
            if not lb_path.is_file():
                print(printable(f"scan-sensitive: local-block file not found: {lb_path}"), file=sys.stderr)
                return 2
        else:
            # Set but missing = a mistake, never a silent "no client terms".
            env = os.environ.get(LOCAL_BLOCK_ENV)
            if env and not Path(env).is_file():
                print(printable(f"scan-sensitive: {LOCAL_BLOCK_ENV} names a file that does not exist: {env}"),
                      file=sys.stderr)
                return 2
            lb_path = default_local_block(repo)
        local = load_local_block(lb_path)
        if local is None:
            print(f"scan-sensitive: WARNING: no local-block terms ({LOCAL_BLOCK_REL} not found in "
                  "this checkout or its main checkout, or it has none): client, host and tailnet "
                  "names are NOT checked, only secret shapes. Create it (SECURITY.md), or pass "
                  "--no-local-block to say so on purpose.", file=sys.stderr)

    try:
        if args.staged:
            findings = scan_staged(repo, publish=args.publish, local=local)
        elif args.message:
            try:
                raw = args.message.read_bytes()
            except OSError as exc:
                print(f"scan-sensitive: {exc}", file=sys.stderr)
                return 2
            decoded = decode_text(raw)
            # git runs commit-msg with GIT_EDITOR=: when no editor was used (-m, -F, --no-edit).
            editor = os.environ.get("GIT_EDITOR") != ":"
            text = message_file_text(decoded[0] if decoded else raw.decode("utf-8", "replace"),
                                     editor=editor, config=message_config(repo) if editor else MessageConfig())
            findings = scan_message(COMMIT_MESSAGE, text, publish=args.publish, local=local)
        elif args.range_spec:
            tips: Optional[list[str]] = None
            if args.remote_tips is not None:
                try:
                    listing = args.remote_tips.read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    print(f"scan-sensitive: {exc}", file=sys.stderr)
                    return 2
                tips = remote_tips(repo, listing)
            findings = scan_range(repo, args.range_spec, args.remote, publish=args.publish, local=local,
                                  tips=tips)
        elif args.ref_names:
            findings = [f for name in args.ref_names
                        for f in scan_ref_name(name, local=local, publish=args.publish)]
        elif args.all_history:
            findings = scan_all_history(repo, publish=args.publish, local=local)
        else:
            root = (args.root or repo).resolve()
            use_git = args.root is None or _toplevel(root) == root
            findings = scan_tree(root, publish=args.publish, local=local, use_git=use_git)
        if findings:
            # Inside the guard: a report that fails half-way is a refusal
            # with the exception's type, like any other internal error.
            _report(findings, args.quiet)
            return 1
        return 0
    except GitError as exc:
        print(printable(f"scan-sensitive: {exc}"), file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - a bug: refuse (exit 2), never print a value
        # A traceback (and the exception's message) can quote the text being
        # scanned. Only the type is printed unless debugging is asked for.
        if os.environ.get(DEBUG_ENV) == "1":
            raise
        print(f"scan-sensitive: internal error ({type(exc).__name__}); nothing was checked to the "
              f"end, so this is a refusal (exit 2). Rerun with {DEBUG_ENV}=1 for the traceback "
              "(it may print the value being scanned: never paste it anywhere).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
