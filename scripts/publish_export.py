#!/usr/bin/env python3
"""publish_export.py: choose, copy and neutralize the files of a public copy.

The file-handling half of ``scripts/publish_public.sh``, which is the only
supported way to make a public copy (it also scans the result, refuses on any
finding, and makes the orphan commit). Not meant to be run on its own.

* Source: the files committed at ``--ref``, never the working tree, so an
  uncommitted scratch file cannot ride along.
* Selection: ``--allowlist`` globs (relative to the repo root; ``*`` stays in
  one directory, ``**`` crosses directories, a trailing ``/`` means everything
  under it; later lines win; ``!glob`` takes paths back out). A fixed
  hard-exclude list applies whatever the allowlist says. Symlinks and
  submodules are never exported.
* Neutralizing: ``--map`` lines ``real => neutral`` (case-insensitive
  literal) or ``re:<regex> => neutral``, applied to text contents and to path
  names. The map is local and gitignored (``.githooks/.publish-map``): it
  holds the real strings.

Prints the exported (mapped) paths, one per line.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import scan_sensitive as ss  # noqa: E402

# Never published, whatever the allowlist says.
HARD_EXCLUDES = (
    "**/internal/**", "**/INTERNAL-*", "docs/sessions/**", "docs/leak-events/**",
    # Working notes: status, hand-offs, reviews, the scrub inventory, agent state.
    "**/STATE.md", "docs/handoffs/**", "docs/design-handoff/**", "docs/reviews/**",
    "**/PRE-PUBLIC-SCRUB*", "**/.claude/**",
    # Deployment and infrastructure: ops/ holds the per-host trees (the bundle
    # host, the legacy host, the backup vault), compose files, systemd units
    # and the public allowlist itself. A public copy carries none of it.
    "ops/**",
    # Host access and infrastructure state, wherever it sits; sealed (age)
    # backups and archives are ciphertext of real data, still never public.
    "**/.ssh/**", "**/known_hosts", "**/authorized_keys*",
    "**/*.tfstate", "**/*.tfstate.*", "**/*.tfvars", "**/*.ovpn",
    "**/kubeconfig", "**/*.kubeconfig", "**/*.age",
    ".githooks/.local-block", ".githooks/.publish-map",
    "**/.env", "**/.env.*", "**/*.env",
    "**/*.gpg", "**/*.gpg.*", "**/*.pgp", "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx",
    "**/*.ppk", "**/*.kdbx", "**/id_rsa*", "**/id_dsa*", "**/id_ecdsa*", "**/id_ed25519*",
    "**/*.db", "**/*.db-*", "**/*.sqlite", "**/*.sqlite3", "**/*.bak", "**/*.dump",
    "**/secrets/**", "credentials/**",
)


def glob_to_regex(pattern: str) -> "re.Pattern[str]":
    pat = pattern.strip().lstrip("/")
    if pat.endswith("/"):
        pat += "**"
    out: list[str] = []
    i = 0
    while i < len(pat):
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("/**", i) and i + 3 == len(pat):
            out.append("(?:/.*)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        elif pat[i] == "[":
            j = pat.find("]", i + 1)
            if j == -1:
                out.append(re.escape(pat[i]))
                i += 1
            else:
                out.append(pat[i:j + 1])
                i = j + 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def load_allowlist(path: Path) -> list[tuple[bool, "re.Pattern[str]"]]:
    rules: list[tuple[bool, "re.Pattern[str]"]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        negate = line.startswith("!")
        rules.append((not negate, glob_to_regex(line[1:] if negate else line)))
    return rules


_HARD = [glob_to_regex(p) for p in HARD_EXCLUDES]


def allowed(path: str, rules: list[tuple[bool, "re.Pattern[str]"]]) -> bool:
    verdict = False
    for include, rx in rules:
        if rx.match(path):
            verdict = include
    return verdict


def hard_excluded(path: str) -> bool:
    return any(rx.match(path) for rx in _HARD)


def load_map(path: Optional[Path]) -> list[tuple["re.Pattern[str]", str]]:
    if path is None or not path.is_file():
        return []
    literals: list[tuple[str, str]] = []
    regexes: list[tuple["re.Pattern[str]", str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or " => " not in line:
            continue
        real, neutral = line.split(" => ", 1)
        real, neutral = real.strip(), neutral.strip()
        if not real:
            continue
        if real.startswith("re:"):
            regexes.append((re.compile(real[3:], re.I), neutral))
        else:
            literals.append((real, neutral))
    literals.sort(key=lambda kv: -len(kv[0]))
    return [(re.compile(re.escape(r), re.I), n) for r, n in literals] + regexes


def apply_map(text: str, mapping: list[tuple["re.Pattern[str]", str]]) -> str:
    for rx, neutral in mapping:
        text = rx.sub(lambda _m, n=neutral: n, text)
    return text


def tree_entries(repo: Path, ref: str) -> list[tuple[str, str, str]]:
    """(mode, sha, path) of every blob at ``ref``."""
    out = ss._git(repo, "ls-tree", "-r", "-z", "--full-tree", ref)
    entries = []
    for item in out.split("\0"):
        if not item:
            continue
        meta, path = item.split("\t", 1)
        mode, kind, sha = meta.split()
        if kind == "blob" and mode != "120000":
            entries.append((mode, sha, path))
    return entries


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="publish_export.py")
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--ref", default="HEAD")
    ap.add_argument("--allowlist", type=Path, required=True)
    ap.add_argument("--map", type=Path)
    ap.add_argument("--out", type=Path, help="export directory (must be empty or absent)")
    ap.add_argument("--list", action="store_true", help="only print what would be exported")
    args = ap.parse_args(argv)

    rules = load_allowlist(args.allowlist)
    mapping = load_map(args.map)
    if not args.list:
        if args.out is None:
            ap.error("--out is required unless --list")
        if args.out.exists() and any(args.out.iterdir()):
            print(f"publish_export: {args.out} is not empty; refusing", file=sys.stderr)
            return 2
        args.out.mkdir(parents=True, exist_ok=True)

    try:
        entries = tree_entries(args.repo, args.ref)
    except ss.GitError as exc:
        print(f"publish_export: {exc}", file=sys.stderr)
        return 2

    reader = None if args.list else ss._BlobReader(args.repo)
    exported = blocked = renamed = 0
    try:
        for mode, sha, path in entries:
            if not allowed(path, rules):
                continue
            if hard_excluded(path):
                blocked += 1
                print(f"publish_export: hard-excluded (allowlisted, never published): {path}",
                      file=sys.stderr)
                continue
            target = apply_map(path, mapping)
            renamed += target != path
            print(target)
            exported += 1
            if reader is None:
                continue
            data = reader.read(sha)
            if data is None:
                continue
            # Text in any encoding the scanner reads (UTF-16 PowerShell output
            # included) is mapped in that encoding; binary is left as is, and
            # the --publish scan refuses binary that is not an image or a font.
            decoded = ss.decode_text(data)
            if decoded is not None:
                text, codec, bom = decoded
                mapped = apply_map(text, mapping)
                if mapped != text:
                    data = bom + mapped.encode(codec)
            dest = args.out / target
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            os.chmod(dest, 0o755 if mode == "100755" else 0o644)
    finally:
        if reader is not None:
            reader.close()
    print(f"publish_export: {exported} file(s) selected, {renamed} renamed by the map, "
          f"{blocked} hard-excluded; {len(mapping)} map entr{'y' if len(mapping) == 1 else 'ies'}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
