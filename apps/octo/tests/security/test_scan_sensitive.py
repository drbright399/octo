"""scripts/scan_sensitive.py: allow markers, local terms, masking, never-commit
files, and the --tree / --staged / --range / --publish modes."""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import time

import pytest

from apps.octo.security import secret_patterns as sp
from apps.octo.tests.security import fakes
from apps.octo.tests.security.conftest import REPO_ROOT, SCANNER

_SPEC = importlib.util.spec_from_file_location("scan_sensitive", SCANNER)
ss = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("scan_sensitive", ss)  # dataclasses resolve their module by name
_SPEC.loader.exec_module(ss)

SECRET = fakes.rand("scan-secret", 32)
ASSIGN = f"client_secret = '{SECRET}'"
MARK = sp.ALLOW_MARKER  # built from parts, so this file carries no marker of its own


def _detectors(findings) -> list[str]:
    return [f.detector for f in findings]


# --------------------------------------------------------------------------- #
# allow marker
# --------------------------------------------------------------------------- #

def test_allow_marker_with_a_reason_suppresses_the_line():
    text = f"{ASSIGN}  # {MARK} generated test vector, never a live key\n"
    assert ss.scan_text("app/x.py", text) == []


def test_allow_marker_without_a_reason_is_itself_a_finding_and_allows_nothing():
    for bare in (f"{ASSIGN}  # {MARK}\n", f"{ASSIGN}  # {MARK}:  \n", f"{ASSIGN}  # {MARK} -\n"):
        names = _detectors(ss.scan_text("app/x.py", bare))
        assert "allow-marker-without-reason" in names and "secret-assignment" in names


def test_allow_marker_on_a_comment_line_covers_the_next_line_only():
    text = f"# {MARK} fixture for the redaction test\n{ASSIGN}\n{ASSIGN}\n"
    found = ss.scan_text("app/x.py", text)
    assert [(f.line, f.detector) for f in found] == [(3, "secret-assignment")]
    # a marker trailing a code line does not reach the line below it
    text2 = f"x = 1  # {MARK} unrelated reason\n{ASSIGN}\n"
    assert [f.line for f in ss.scan_text("app/x.py", text2)] == [2]


# --------------------------------------------------------------------------- #
# local sensitive terms
# --------------------------------------------------------------------------- #

def test_local_block_terms_are_found_masked_and_cannot_be_allowed(tmp_path):
    block = tmp_path / ".local-block"
    block.write_text("# client names\nZebra Clinic\nhost-[0-9]+\\.corp\n(unclosed\n[[:alpha:]]*\n")
    rx = ss.load_local_block(block)
    text = (f"visit zebra clinic today  # {MARK} looks fine to me\n"
            "ssh host-42.corp\nsee (unclosed paren\n")
    found = ss.scan_text("docs/x.md", text, local=rx)
    assert [(f.line, f.detector) for f in found] == [
        (1, "local-block"), (2, "local-block"), (3, "local-block")]
    rendered = "\n".join(f.render() for f in found)
    assert "zebra clinic" not in rendered.lower() and "host-42" not in rendered
    # a term in a file path counts too
    assert _detectors(ss.path_findings("clients/zebra-clinic/notes.md", b"", rx)) == []
    assert _detectors(ss.path_findings("clients/Zebra Clinic/notes.md", b"", rx)) == ["local-block"]


def test_default_local_block_comes_from_the_repo(make_repo, monkeypatch):
    repo = make_repo()
    repo.write(".githooks/.local-block", "Zebra Clinic\n")
    monkeypatch.delenv("SCAN_SENSITIVE_LOCAL_BLOCK", raising=False)
    assert ss.default_local_block(repo.path) == repo.path / ".githooks" / ".local-block"


def _run_scanner(cwd, env, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCANNER), *args], cwd=cwd, env=env,
                          capture_output=True, text=True)


def test_a_block_list_variable_naming_a_missing_file_is_an_error(make_repo, tmp_path):
    # Set but missing must never mean "no client terms": exit 2, like --local-block.
    repo = make_repo()
    env = dict(repo.env, SCAN_SENSITIVE_LOCAL_BLOCK=str(tmp_path / "missing-block-list"))
    for mode in (["--ref-name", "refs/heads/topic"], ["--staged"], ["--tree"]):
        proc = _run_scanner(repo.path, env, *mode)
        assert proc.returncode == 2 and "does not exist" in proc.stderr, (mode, proc.stderr)
    # an explicit --local-block wins over the variable; --no-local-block is the opt-out
    block = tmp_path / "block"
    block.write_text("Zebra Clinic\n")
    assert _run_scanner(repo.path, env, "--local-block", str(block),
                        "--ref-name", "refs/heads/topic").returncode == 0
    assert _run_scanner(repo.path, env, "--no-local-block",
                        "--ref-name", "refs/heads/topic").returncode == 0


def test_no_block_list_is_said_out_loud(make_repo):
    repo = make_repo()
    proc = repo.scan("--ref-name", "refs/heads/topic")
    assert proc.returncode == 0 and "no local-block terms" in proc.stderr
    repo.write(".githooks/.local-block", "# comments only, no terms\n")
    assert "no local-block terms" in repo.scan("--ref-name", "refs/heads/topic").stderr
    proc = repo.scan("--no-local-block", "--ref-name", "refs/heads/topic")
    assert proc.returncode == 0 and "local-block" not in proc.stderr


BLOCKED = "glo" + "bex"  # assembled at runtime; checked case-insensitively in output


@pytest.mark.parametrize("name,hit", [
    (f"refs/heads/{BLOCKED}-onboarding", True),
    (f"refs/heads/{BLOCKED}_onboarding", True),   # '_' is a word character for \b
    (f"refs/heads/feat/{BLOCKED}2", True),        # so is a digit
    (f"refs/tags/v2_{BLOCKED.upper()}", True),
    (f"refs/heads/{BLOCKED}ample", False),        # joined by letters: another word
    ("refs/heads/onboarding", False),
])
def test_ref_names_match_word_bounded_terms_joined_by_underscore_or_digits(tmp_path, name, hit):
    block = tmp_path / ".local-block"
    block.write_text(f"\\<{BLOCKED}\\>\n")
    found = ss.scan_ref_name(name, local=ss.load_local_block(block))
    assert _detectors(found) == (["local-block"] if hit else [])
    assert BLOCKED not in "\n".join(f.render() for f in found).lower()


def test_overlapping_hits_in_a_name_are_masked_whole():
    assert ss._mask_spans("abcdefghij", [(2, 8), (0, 4)]) == sp.mask("abcdefgh") + "ij"
    assert ss._mask_spans("abcdef", []) == "abcdef"


# --------------------------------------------------------------------------- #
# masking
# --------------------------------------------------------------------------- #

def test_output_never_prints_a_full_secret():
    other = fakes.rand("bystander", 30)
    line = f"{ASSIGN}; note = '{other}'\n"
    found = ss.scan_text("app/x.py", line)
    rendered = "\n".join(f.render() for f in found)
    assert found and SECRET not in rendered and other not in rendered
    assert sp.mask(SECRET) in rendered


def test_a_secret_that_starts_with_a_local_block_term_is_masked_whole(tmp_path):
    # Overlapping hits: the shorter term must not leave the rest of the value readable.
    block = tmp_path / ".local-block"
    block.write_text(f"{BLOCKED}\n")
    tail = fakes.rand("after-term", 24)
    value = BLOCKED + tail
    line = f"db_password = '{value}'\n"
    found = ss.scan_text("app/x.py", line, local=ss.load_local_block(block))
    rendered = "\n".join(f.render() for f in found)
    assert {"local-block", "secret-assignment"} <= set(_detectors(found))
    assert tail[:8] not in rendered and BLOCKED not in rendered.lower()


@pytest.mark.parametrize("name", sorted(fakes.positives()))
def test_no_detector_output_contains_its_value(name):
    text = fakes.positives()[name]
    rendered = "\n".join(f.render() for f in ss.scan_text("app/x.txt", text))
    for hit in sp.find_hits(text):
        assert hit.value not in rendered


# --------------------------------------------------------------------------- #
# files that are never committed
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("path,data,expected", [
    ("deploy/.env", b"DATTO_API_URL=https://api.vendor.invalid\n", "forbidden-file:env-with-values"),
    ("deploy/prod.env", b"LOG_LEVEL=INFO\n", "forbidden-file:env-with-values"),
    ("deploy/.env.example", b"DATTO_API_URL=https://api.vendor.invalid\n", None),
    ("deploy/.env", b"API_TOKEN=\nOTHER=${FROM_VAULT}\n", None),
    ("certs/server.pem", b"", "forbidden-file:key-file"),
    ("keys/id_ed25519", b"", "forbidden-file:ssh-key-file"),
    ("keys/id_ed25519.pub", b"", None),
    ("vault/datto.env.gpg", b"", "forbidden-file:encrypted-vault-file"),
    ("state/registry.db", b"", "forbidden-file:database-file"),
    ("tests/fixtures/sample.db", b"", None),
    ("backups/state.tar.gz", b"", "forbidden-file:backup-file"),
    ("notes.md.bak", b"", "forbidden-file:backup-file"),
    (".githooks/.local-block", b"", "forbidden-file:local-terms-file"),
    (".githooks/.publish-map", b"", "forbidden-file:local-terms-file"),
    ("apps/octo/credentials/vault.py", b"", None),
])
def test_never_commit_files(path, data, expected):
    names = _detectors(ss.path_findings(path, data, None))
    assert names == ([expected] if expected else [])


def test_only_lines_limits_the_report_to_added_lines():
    text = f"{ASSIGN}\nx = 1\n{ASSIGN.replace('client', 'other_client')}\n"
    assert [f.line for f in ss.scan_text("a.py", text, only_lines={2})] == []
    assert [f.line for f in ss.scan_text("a.py", text, only_lines={3})] == [3]


def test_binary_content_is_read_as_strings_and_the_name_still_counts():
    noise = fakes.key_bytes("png-noise", 512)  # compressed data: no entropy findings
    assert ss.scan_blob("img/logo.png", b"\x89PNG\0" + noise, publish=False, local=None) == []
    token = "gh" + "p_" + fakes.rand("png-token", 36)
    assert _detectors(ss.scan_blob("img/logo.png", b"\x89PNG\0" + token.encode(), publish=False,
                                   local=None)) == ["github-token"]
    # heuristics (assignments, entropy) are not applied to binary strings
    assert ss.scan_blob("img/logo.png", b"\x89PNG\0" + ASSIGN.encode(), publish=False, local=None) == []
    assert _detectors(ss.scan_blob("dump.sqlite", b"\0" + noise, publish=False,
                                   local=None)) == ["forbidden-file:database-file"]


def test_added_lines_parser_handles_hunks_and_quoted_paths():
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,0 +2,2 @@\n+one\n+two\n"
        "@@ -9 +11 @@\n-old\n+new\n"
        'diff --git "a/sp ace\\"q.py" "b/sp ace\\"q.py"\n--- /dev/null\n+++ "b/sp ace\\"q.py"\n'
        "@@ -0,0 +1 @@\n+x\n"
    )
    assert ss.added_lines(diff) == {"a.py": {2, 3, 11}, 'sp ace"q.py': {1}}


# --------------------------------------------------------------------------- #
# CLI modes
# --------------------------------------------------------------------------- #

def test_tree_mode(make_repo):
    repo = make_repo()
    assert repo.commit("app/ok.py", "x = 1\n").returncode == 0
    assert repo.scan("--tree").returncode == 0
    repo.write("app/creds.py", ASSIGN + "\n")  # untracked files are part of the tree
    proc = repo.scan("--tree")
    assert proc.returncode == 1
    assert "app/creds.py:1: [secret-assignment]" in proc.stdout and SECRET not in proc.stdout


def test_staged_mode_scans_only_what_the_commit_adds(make_repo):
    repo = make_repo()
    repo.commit("app/old.py", ASSIGN + "\nx = 1\n")  # already in history (no hook here)
    repo.write("app/old.py", ASSIGN + "\nx = 2\n")
    repo.git("add", "app/old.py")
    assert repo.scan("--staged").returncode == 0  # the untouched line is not this commit's
    repo.write("app/new.py", "y = 1\n" + ASSIGN + "\n")
    repo.git("add", "app/new.py")
    proc = repo.scan("--staged")
    assert proc.returncode == 1 and "app/new.py:2: [secret-assignment]" in proc.stdout
    assert "app/old.py" not in proc.stdout


def test_staged_mode_refuses_a_never_commit_file(make_repo):
    repo = make_repo()
    repo.write("deploy/.env", "DATTO_API_URL=https://api.vendor.invalid\n")
    repo.git("add", "-f", "deploy/.env")
    proc = repo.scan("--staged")
    assert proc.returncode == 1 and "forbidden-file:env-with-values" in proc.stdout


def test_range_mode(make_repo):
    repo = make_repo()
    repo.commit("a.py", "x = 1\n")
    repo.commit("b.py", ASSIGN + "\n")
    repo.commit("c.py", "z = 3\n")
    sha = repo.git("rev-parse", "HEAD~1").stdout.strip()
    proc = repo.scan("--range", "HEAD~2..HEAD")
    assert proc.returncode == 1 and f"{sha[:10]} b.py:1: [secret-assignment]" in proc.stdout
    assert repo.scan("--range", "HEAD~1..HEAD").returncode == 0
    assert repo.scan("--range", "HEAD").returncode == 1  # no remote: the whole history


def test_range_mode_skips_what_the_remote_already_has(make_repo):
    remote = make_repo("remote.git", bare=True)
    repo = make_repo()
    repo.git("remote", "add", "origin", str(remote.path))
    repo.commit("b.py", ASSIGN + "\n")
    repo.git("push", "-q", "origin", "main")
    repo.commit("c.py", "z = 3\n")
    assert repo.scan("--range", "HEAD", "--remote", "origin").returncode == 0
    # a different remote has none of it: every commit is new there
    assert repo.scan("--range", "HEAD", "--remote", "https://example.invalid/x.git").returncode == 1


def test_range_mode_scans_merge_resolutions(make_repo):
    repo = make_repo()
    repo.commit("a.py", "x = 1\n")
    repo.git("checkout", "-q", "-b", "side")
    repo.commit("s.py", "s = 1\n")
    repo.git("checkout", "-q", "main")
    repo.commit("m.py", "m = 1\n")
    repo.git("merge", "-q", "--no-commit", "side")
    repo.write("evil.py", ASSIGN + "\n")
    repo.git("add", "evil.py")
    repo.git("commit", "-q", "-m", "merge")
    proc = repo.scan("--range", "HEAD~1..HEAD")
    assert proc.returncode == 1 and "evil.py:1:" in proc.stdout


def test_publish_mode_on_a_plain_directory(tmp_path):
    export = tmp_path / "export"
    (export / "docs").mkdir(parents=True)
    (export / "docs" / "net.md").write_text("gateway " + fakes.ip(10, 9, 8, 7) + "\n")
    (export / "node_modules").mkdir()  # nothing in an export is skipped
    (export / "node_modules" / "x.js").write_text("const u = '" + "/ho" + "me/alice/x';\n")
    run = [sys.executable, str(SCANNER), "--root", str(export), "--no-local-block"]
    assert subprocess.run(run + ["--tree"], capture_output=True).returncode == 0
    proc = subprocess.run(run + ["--publish"], capture_output=True, text=True)
    assert proc.returncode == 1
    assert "docs/net.md:1: [ip-private]" in proc.stdout
    assert "node_modules/x.js:1: [home-path]" in proc.stdout


def test_usage_and_git_errors_exit_2(make_repo):
    repo = make_repo()
    repo.commit("a.py", "x = 1\n")
    assert repo.scan().returncode == 2
    assert repo.scan("--range", "no-such-ref").returncode == 2
    listed = repo.scan("--list-detectors")
    assert listed.returncode == 0 and "secret-assignment" in listed.stdout


def test_full_repo_tree_scan_is_fast():
    start = time.monotonic()
    proc = subprocess.run([sys.executable, str(SCANNER), "--tree", "--no-local-block", "-q"],
                          cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode in (0, 1), proc.stderr
    assert time.monotonic() - start < 30
    assert not re.search(r"Traceback", proc.stderr)


# A git-less copy (an export, a public clone's files) has no `git ls-files`:
# the walk leaves out what the copy's own .gitignore keeps out of a commit,
# so a copy holding a dev node_modules (hundreds of MB, minutes to scan)
# still fits the budget.
_HEAVY_DIRS = ("apps/athena/web/node_modules", "packages/.venv", "apps/octo/__pycache__",
               "apps/athena/web/dist", "build")
_HOME_PATH_JS = "const u = '" + "/ho" + "me/alice/x';\n"


def _gitless_copy(dest) -> None:
    """This tree's files as git lists them (as the walk does, in a copy), no .git."""
    for rel in ss.tree_files(REPO_ROOT, use_git=ss._toplevel(REPO_ROOT) == REPO_ROOT):
        src = REPO_ROOT / rel
        if src.is_symlink() or not src.is_file():
            continue
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest / rel)


def test_full_repo_scan_without_git_skips_the_ignored_heavy_dirs(tmp_path):
    export = tmp_path / "export"
    export.mkdir()
    _gitless_copy(export)
    assert (export / ".gitignore").is_file() and not (export / ".git").exists()
    for heavy in _HEAVY_DIRS:  # many files, a finding in each
        for i in range(300):
            js = export / heavy / f"pkg{i % 30}" / f"m{i}.js"
            js.parent.mkdir(parents=True, exist_ok=True)
            js.write_text(_HOME_PATH_JS + "var x = 1;\n" * 300)
    planted = "docs/planted-export-check.md"  # a file git would commit: the walk ran
    (export / planted).write_text("gateway " + fakes.ip(10, 9, 8, 7) + "\n")
    (export / "tools" / "build").mkdir(parents=True)  # brought back by a nested .gitignore
    (export / "tools" / ".gitignore").write_text("!build/\n")
    (export / "tools" / "build" / "kept.js").write_text(_HOME_PATH_JS)
    start = time.monotonic()
    proc = subprocess.run([sys.executable, str(SCANNER), "--tree", "--publish", "--no-local-block",
                           "--root", str(export)], cwd=export, capture_output=True, text=True)
    assert time.monotonic() - start < 30
    assert proc.returncode == 1, proc.stderr
    assert "Traceback" not in proc.stderr
    reported = {line.split(":", 1)[0] for line in proc.stdout.splitlines() if ": [" in line}
    assert planted in reported and "tools/build/kept.js" in reported
    assert not [p for p in reported if p.startswith(tuple(h + "/" for h in _HEAVY_DIRS))]


@pytest.mark.parametrize("gitignore, walked", [
    ("node_modules/\n", False),
    ("**/node_modules\n", False),
    ("", True),  # nothing ignores it: everything is what would be committed
    ("/node_modules/\n", True),  # anchored: only the top-level one is ignored
    ("node_modules/\n!node_modules/\n", True),  # re-included
    ("node_modules/\n!*\n", True),  # a negation glob that could re-include it
    ("node_modules/  \r\n", False),  # git trims trailing spaces and the CR of CRLF
    ("node_modules\t\n", True),  # but not a tab: git matches no "node_modules" with it
])
def test_the_git_less_walk_skips_only_what_gitignore_surely_ignores(tmp_path, gitignore, walked):
    (tmp_path / ".gitignore").write_bytes(gitignore.encode())
    (tmp_path / "web" / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "web" / "node_modules" / "pkg" / "x.js").write_text("x\n")
    (tmp_path / "web" / "app.js").write_text("x\n")
    files = list(ss.tree_files(tmp_path, use_git=False))
    assert "web/app.js" in files
    assert ("web/node_modules/pkg/x.js" in files) is walked


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_a_top_gitignore_that_is_not_a_plain_file_skips_nothing(tmp_path, kind):
    """git does not follow a symlinked .gitignore (it would commit node_modules
    here), and a FIFO is never opened (the walk would block on it)."""
    tree = tmp_path / "tree"
    (tree / "node_modules").mkdir(parents=True)
    (tree / "node_modules" / "x.js").write_text("x\n")
    if kind == "symlink":
        (tmp_path / "elsewhere").write_text("node_modules/\n")
        (tree / ".gitignore").symlink_to(tmp_path / "elsewhere")
    else:
        os.mkfifo(tree / ".gitignore")
    assert "node_modules/x.js" in list(ss.tree_files(tree, use_git=False))
