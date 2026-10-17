"""Guardrails v9 (2026-10-16, the public standard for the private tree): the
publish-only ``memory-path`` detector.

A link or a path into an agent's memory store (the memory directory of a
Claude Code projects entry: any prefix, ``../`` relative, ``~``, ``$HOME``,
absolute, Windows, JSON-escaped) and a home-directory project slug on its own
(``-home-<user>``, ``-Users-<user>``, ``C--Users-<user>``) are never public:
they carry the operator's user name and directory layout, and say what the
working notes are about. The 2026-10-16 sweep found one such link in the tree
(a relative Markdown link: the home-path detector wants an absolute
``/home/<user>``, so nothing saw it).

A note name on its own (no path, no brackets) is NOT reported: Rick allows
those unless they name a client or our infrastructure, which the local-block
terms catch.

Every value is built at run time, so this file passes the scanner it tests."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from apps.octo.security import secret_patterns as sp
from apps.octo.tests.security import hostile
from apps.octo.tests.security.conftest import REPO_ROOT, SCANNER

_SPEC = importlib.util.spec_from_file_location("scan_sensitive", SCANNER)
ss = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("scan_sensitive", ss)  # dataclasses resolve their module by name
_SPEC.loader.exec_module(ss)

NAME = "memory-path"
CLAUDE = ".cla" + "ude"   # assembled: no literal store path in this file
HOME = "-ho" + "me-"
USERS = "-Us" + "ers-"
USER = "alice"
NOTE = "project_" + "widget_rollout_blocker.md"
MARKER = sp.ALLOW_MARKER


def store(prefix: str = "", *, slug: str = HOME + USER, sep: str = "/", tail: str = NOTE) -> str:
    """``<prefix>`` + the memory directory of a projects entry + ``tail``."""
    return f"{prefix}{CLAUDE}{sep}projects{sep}{slug}{sep}memory{sep}{tail}"


def _cpu(fn, *args) -> float:
    start = time.process_time()
    fn(*args)
    return time.process_time() - start


def _hits(text: str, *, publish: bool = True) -> list[sp.Hit]:
    return [h for h in sp.find_hits(text, publish=publish) if h.detector == NAME]


def _render(findings) -> str:
    return "\n".join(f.render() for f in findings)


def _fill(unit: str, size: int) -> str:
    return (unit * (size // len(unit) + 1))[:size]


def test_the_version_is_at_least_9():
    assert ss.GUARDRAILS_VERSION >= 9  # test_lockfile_integrity_local_block pins the current one


def test_memory_path_is_a_publish_only_name_and_listed():
    assert NAME in sp.PUBLISH_ONLY_NAMES and NAME in sp.REPORTED_NAMES
    d = next(d for d in sp.DETECTORS if d.name == NAME)
    assert d.publish_only and not d.redact and d.check is None
    # after the home-path detector (an absolute prefix is reported as a home
    # path of its own), before the double-bracket memory links
    assert sp.DETECTOR_NAMES.index("home-path") < sp.DETECTOR_NAMES.index(NAME) \
        < sp.DETECTOR_NAMES.index("memory-link")
    proc = subprocess.run([sys.executable, str(SCANNER), "--list-detectors"], capture_output=True, text=True)
    assert proc.returncode == 0 and f"{NAME} (--publish)" in proc.stdout.splitlines()


# --------------------------------------------------------------------------- #
# What it finds
# --------------------------------------------------------------------------- #

_STORE_FORMS = {
    # the sweep's find: a relative Markdown link out of docs/sessions/
    "markdown-relative-link": (f"   in [`{NOTE}`]({store('../../../')})).", store()),
    "tilde": (f"notes live in ~/{store()} now", store()),
    "home-variable": (f'cat "$HOME/{store()}"', store()),
    "dot-relative": (f"see ./{store()}", store()),
    "no-prefix": (f"{store()} is the index", store()),
    "directory-only": (f"ls ~/{store(tail='')}", store(tail="")),
    "no-trailing-separator": (f"under ~/{store(tail='')[:-1]}.", store(tail="")[:-1]),
    "closing-parenthesis": (f"(see ~/{store(tail='')[:-1]})", store(tail="")[:-1]),
    "any-slug": (f"~/{store(slug='repo')}", store(slug="repo")),
    "placeholder-slug": (f"~/{store(slug='<project>')}", store(slug="<project>")),
    "glob-slug": (f"ls ~/{store(slug='*', tail='')}", store(slug="*", tail="")),
    "nested-tail": (f"~/{store(tail='archive/' + NOTE)}", store(tail="archive/" + NOTE)),
    "windows": (f"type %USERPROFILE%\\{store(slug='C--Users-' + USER, sep=chr(92))}",
                store(slug="C--Users-" + USER, sep="\\")),
    "json-escaped": ('{"path": "' + store(slug="C--Users-" + USER, sep="\\\\") + '"}',
                     store(slug="C--Users-" + USER, sep="\\\\")),
    "upper-case": (f"~/{store(slug='Repo').upper()}", store(slug="Repo").upper()),
    "in-quotes": (f"open('{store()}')", store()),
}


@pytest.mark.parametrize("text, value", list(_STORE_FORMS.values()), ids=list(_STORE_FORMS))
def test_a_path_into_a_memory_store_is_found_whole(text, value):
    hits = _hits(text)
    assert [h.value for h in hits] == [value]
    assert not _hits(text, publish=False)  # publish-only: no secret, the --publish checks report it


_SLUG_FORMS = {
    "linux": (f"project dir {HOME}{USER}-work-repo holds transcripts", f"{HOME}{USER}-work-repo"),
    "linux-bare-user": (f"slug {HOME}{USER}", f"{HOME}{USER}"),
    "macos": (f"slug {USERS}{USER}-src", f"{USERS}{USER}-src"),
    "windows": (f"slug C-{USERS}{USER}-work", f"C-{USERS}{USER}-work"),
    "line-start": (f"{HOME}{USER}/abc.jsonl", f"{HOME}{USER}"),
    "path-component": (f"~/{CLAUDE}/projects/{HOME}{USER}/abc.jsonl", f"{HOME}{USER}"),
    "quoted": (f'slug = "{HOME}{USER}"', f"{HOME}{USER}"),
    "dotted-user": (f"slug {HOME}a.lice", f"{HOME}a.lice"),
}


@pytest.mark.parametrize("text, value", list(_SLUG_FORMS.values()), ids=list(_SLUG_FORMS))
def test_a_home_directory_project_slug_is_found_on_its_own(text, value):
    assert [h.value for h in _hits(text)] == [value]
    assert not _hits(text, publish=False)


def test_an_absolute_store_path_reports_the_home_path_too():
    text = "/ho" + f"me/{USER}/{store()}"
    names = [(h.detector, h.value) for h in sp.find_hits(text, publish=True)]
    assert names == [("home-path", "/ho" + f"me/{USER}"), (NAME, store())]
    windows = "C:" + "\\Users\\" + USER + "\\" + store(slug="C--Users-" + USER, sep="\\")
    assert [h.detector for h in sp.find_hits(windows, publish=True)] == ["home-path", NAME]


def test_two_paths_on_one_line_are_two_hits():
    text = f"a ~/{store()} and b ~/{store(slug='repo', tail='')}"
    assert [h.value for h in _hits(text)] == [store(), store(slug="repo", tail="")]


# --------------------------------------------------------------------------- #
# What it leaves alone
# --------------------------------------------------------------------------- #

_NEGATIVES = {
    # note names on their own: allowed (Rick, 2026-10-16), no detector
    "bare-note-name": "see feedback_vault_rules and " + NOTE,
    "note-name-in-backticks": f"tracked as `{NOTE}` in the internal notes",
    "memory-index": "loaded every session via `MEMORY.md`",
    # the rest of the agent's directory is no memory store
    "skills": f"skills in ~/{CLAUDE}/skills/ or the repo's {CLAUDE}/skills/",
    "settings": f"{CLAUDE}/settings.json",
    "transcript-of-a-repo-slug": f"~/{CLAUDE}/projects/repo/abc.jsonl",
    "memory-file-not-dir": f"~/{CLAUDE}/projects/repo/memory.md",
    "memory-prefix-word": f"~/{CLAUDE}/projects/repo/memory-bank/x",
    "memory-joined-word": f"~/{CLAUDE}/projects/repo/memorybank/x",
    "memory-underscore": f"~/{CLAUDE}/projects/repo/memory_x/y",
    "not-the-dot-dir": f"tool{CLAUDE}/projects/repo/memory/x",
    "blank-slug": f"~/{CLAUDE}/projects/ /memory/x",
    # placeholders and look-alikes of the slug
    "placeholder-user": f"slug {HOME}<user>",
    "variable-user": f"slug {HOME}$USER and {HOME}${{USER}}",
    "brace-user": f"slug {HOME}{{user}}",
    "dash-user": f"slug {HOME}-x",
    "bare-slug-head": f"suffix '{HOME}' + name",
    "double-dash-option": "--ho" + "me-dir /srv",
    # a drive letter leads only the Windows slug (C--Users-<user>)
    "drive-letter-before-home": "flags v-" + HOME + "dir and C-" + HOME + USER,
    "inside-a-word": "at" + HOME + "lab, nav" + HOME + "link, btn" + HOME + "x",
    "markdown-anchor": "[top](#" + HOME + "page) and [x](doc.md#" + HOME + "page)",
    "after-a-dot": "x." + HOME + "y",
    "capitalized-home": "-Ho" + "me-alice",
    "lower-case-users": "-us" + "ers-alice",
}


@pytest.mark.parametrize("text", list(_NEGATIVES.values()), ids=list(_NEGATIVES))
def test_names_layouts_and_look_alikes_are_not_reported(text):
    assert not _hits(text)


def test_a_bare_note_name_is_no_finding_of_any_detector():
    # no detector for bracketless note names: the double-bracket form only
    text = "tracked as " + NOTE + " (see feedback_vault_rules)\n"
    assert ss.scan_text("docs/x.md", text, publish=True) == []
    assert [f.detector for f in ss.scan_text("docs/x.md", "[" + "[feedback_vault_rules]" + "]\n",
                                             publish=True)] == ["memory-link"]


def test_job_output_is_not_redacted_for_a_path():
    text = f"wrote ~/{store()}"
    assert sp.redact(text) == (text, 0)


# --------------------------------------------------------------------------- #
# Masked output: the user name and the note name never print
# --------------------------------------------------------------------------- #

_SECRETS = (USER, "widget", "rollout", "projects" + "/" + HOME)


def _clean(out: str) -> bool:
    return not any(s in out for s in _SECRETS)


@pytest.mark.parametrize("line", [
    _STORE_FORMS["markdown-relative-link"][0],
    _STORE_FORMS["tilde"][0],
    _STORE_FORMS["json-escaped"][0],
    _SLUG_FORMS["linux"][0],
    _SLUG_FORMS["windows"][0],
    "/ho" + f"me/{USER}/{store()}",
])
def test_the_excerpt_masks_the_path(line):
    found = ss.scan_text("docs/sessions/notes.md", line + "\n", publish=True)
    rendered = _render(found)
    assert NAME in [f.detector for f in found], rendered
    assert _clean(rendered), rendered
    assert "***(" in rendered


def test_the_cli_reports_it_masked(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "notes.md").write_text("# Notes\n\nok\n" + _STORE_FORMS["markdown-relative-link"][0]
                                                + "\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, str(SCANNER), "--tree", "--publish", "--root", str(tmp_path),
                           "--no-local-block"], capture_output=True, text=True, cwd=tmp_path)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and f"docs/notes.md:4: [{NAME}]" in out, out
    assert _clean(out) and "Traceback" not in out, out
    # the secret-shape scan alone (no --publish) does not report it
    proc = subprocess.run([sys.executable, str(SCANNER), "--tree", "--root", str(tmp_path), "--no-local-block"],
                          capture_output=True, text=True, cwd=tmp_path)
    assert proc.returncode == 0 and NAME not in proc.stdout, proc.stdout + proc.stderr


def test_a_file_name_with_the_path_is_a_finding_and_printed_masked():
    path = f"docs/{store(tail='')}x.md"
    found = ss.path_findings(path, b"", None, publish=True)
    rendered = _render(found)
    assert f"path:{NAME}" in [f.detector for f in found] and _clean(rendered), rendered
    assert ss.display_path(path, None) != path


def test_a_ref_name_with_a_home_slug_is_refused_masked():
    found = ss.scan_ref_name(f"refs/heads/notes/{HOME}{USER}", local=None, publish=True)
    rendered = _render(found)
    assert [f.detector for f in found] == [f"ref:{NAME}"] and _clean(rendered), rendered
    assert ss.scan_ref_name(f"refs/heads/notes/{HOME}{USER}", local=None, publish=False) == []


# --------------------------------------------------------------------------- #
# Allow markers: only one that names the detector
# --------------------------------------------------------------------------- #

def test_a_bare_allow_marker_does_not_cover_it():
    line = f"{store()}  # {MARKER} the layout of a fixture repository\n"
    assert [f.detector for f in ss.scan_text("docs/x.py", line, publish=True)] == [NAME]


def test_a_marker_naming_the_detector_covers_it():
    line = f"{store()}  # {MARKER}[{NAME}] the layout of a fixture repository\n"
    assert ss.scan_text("docs/x.py", line, publish=True) == []
    above = f"# {MARKER}[{NAME}] the layout of a fixture repository\n{store()}\n"
    assert ss.scan_text("docs/x.py", above, publish=True) == []
    other = f"{store()}  # {MARKER}[home-path] the layout of a fixture repository\n"
    assert [f.detector for f in ss.scan_text("docs/x.py", other, publish=True)] == [NAME]


# --------------------------------------------------------------------------- #
# Hostile input: linear, bounded per candidate
# --------------------------------------------------------------------------- #

_RUNS = {
    "projects-heads": f"{CLAUDE}/projects/",
    "projects-heads-backslash": f"{CLAUDE}\\\\projects\\\\",
    "slug-then-no-memory": f"{CLAUDE}/projects/repo/",
    "memory-dirs-glued": f"{CLAUDE}/projects/repo/memory",
    "memory-dirs-joined": f"{CLAUDE}/projects/repo/memory/",
    "memory-near-miss": f"{CLAUDE}/projects/repo/memor/",
    "dot-dirs": CLAUDE,
    "home-slugs": HOME,
    "home-slugs-joined": HOME + "a",
    "home-slugs-spaced": HOME + "a ",
    "drive-dashes": "C-",
    "users-slugs": "C-" + USERS,
}
_TAILS = ("", "a", "-", "/", "\\", ".", " ")


@pytest.mark.parametrize("tail", _TAILS, ids=[repr(t) for t in _TAILS])
@pytest.mark.parametrize("unit", list(_RUNS.values()), ids=list(_RUNS))
def test_runs_of_candidates_stay_within_the_budget(unit, tail):
    text = _fill(unit, hostile.SIZE // 2) + _fill(tail or "x", hostile.SIZE // 2)
    d = next(d for d in sp.DETECTORS if d.name == NAME)
    for purpose in ("scan", "redact"):
        assert _cpu(sp.detector_hits, d, text, sp.Context(), purpose) < hostile.budget(text) / 4
    assert _cpu(lambda: sp.find_hits(text, publish=True)) < hostile.budget(text)
    line = text + "\n"
    assert _cpu(lambda: ss.scan_text("ops/hostile.txt", line, publish=True)) < hostile.budget(line) * 2


def test_a_long_slug_or_tail_is_bounded():
    big = store(slug="a" * hostile.BIG, tail="")
    assert _cpu(lambda: sp.find_hits(big, publish=True)) < hostile.budget(big)
    long_tail = store(tail="b" * hostile.BIG)
    hits = _hits(long_tail)
    assert hits and hits[0].start == 0 and len(hits[0].value) < 600


def test_the_hostile_seeds_carry_the_needles():
    d = next(d for d in sp.DETECTORS if d.name == NAME)
    seeds = hostile.seeds_of(d)
    assert CLAUDE in seeds and HOME in seeds
    assert any(text for _, text in hostile.detector_inputs(d) if len(text) >= hostile.SIZE)


DEADLINE = 180  # seconds for the memory-path hostile run (a few seconds here)


def test_the_hostile_harness_times_memory_path(tmp_path):
    """``hostile.py memory-path`` in a subprocess, killed at DEADLINE: the
    detector alone (scan and redact) on every hostile line built from its
    needles, literals and sampled matches, then the whole pipeline
    (find_hits, redact, the job-output normaliser, the scanner's masked
    report) on the heaviest, and that line stretched to 200 kB."""
    out = tmp_path / "calls.jsonl"
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT), PYTHONDONTWRITEBYTECODE="1")
    with out.open("w") as fh:
        proc = subprocess.Popen([sys.executable, "-m", "apps.octo.tests.security.hostile", NAME],
                                stdout=fh, stderr=subprocess.PIPE, cwd=REPO_ROOT, env=env, text=True)
        try:
            _, err = proc.communicate(timeout=DEADLINE)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, err = proc.communicate()
            pytest.fail(f"the hostile run hit its {DEADLINE} s deadline: {err[-800:]}")
    rows = [json.loads(line) for line in Path(out).read_text().splitlines() if line.strip()]
    assert rows and rows[-1] == {"done": True}, (err or "")[-800:]
    mine = [r for r in rows if r.get("target") == NAME]
    started = {(r["input"], r["path"]) for r in mine if r.get("start")}
    finished = {(r["input"], r["path"]): r for r in mine if "seconds" in r}
    assert started and started == set(finished)
    slow = sorted(((r["seconds"], key) for key, r in finished.items()
                   if r["seconds"] > hostile.BUDGET * max(1.0, r["size"] / hostile.SIZE)), reverse=True)
    assert not slow, slow[:5]
    paths = {r["path"] for r in finished.values()}
    assert {"detector:scan", "detector:redact", "find_hits", "redact", "normalize", "scan_text"} <= paths
    assert max(r["size"] for r in finished.values()) >= hostile.BIG
