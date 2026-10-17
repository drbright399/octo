"""Red-team round 1 (2026-10-09), scanner findings: diff parsing that failed
open, files that were never read, allow markers that allowed too much,
commit / tag messages and file names that were never scanned."""
from __future__ import annotations

import importlib.util
import subprocess
import sys

import pytest

from apps.octo.security import secret_patterns as sp
from apps.octo.tests.security import fakes
from apps.octo.tests.security.conftest import SCANNER

_SPEC = importlib.util.spec_from_file_location("scan_sensitive", SCANNER)
ss = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("scan_sensitive", ss)
_SPEC.loader.exec_module(ss)

TOKEN = "gh" + "p_" + fakes.rand("rt-scan-token", 36)
LEAK = f'GITHUB_TOKEN = "{TOKEN}"\n'
MARK = sp.ALLOW_MARKER


def _detectors(findings) -> list[str]:
    return [f.detector for f in findings]


# --------------------------------------------------------------------------- #
# The diff parser (findings 2 and 3)
# --------------------------------------------------------------------------- #

def test_an_added_line_that_starts_with_plus_plus_is_content_not_a_header():
    diff = (
        "diff --git a/notes.py b/notes.py\nnew file mode 100644\n--- /dev/null\n+++ b/notes.py\n"
        "@@ -0,0 +1,3 @@\n+Notes\n+++ counter bumped\n+GITHUB_TOKEN = 'x'\n"
        "diff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n@@ -2 +2 @@\n--- old\n+new\n"
    )
    assert ss.added_lines(diff) == {"notes.py": {1, 2, 3}, "b.py": {2}}


def test_a_file_the_patch_does_not_account_for_is_scanned_whole(make_repo):
    repo = make_repo()
    repo.write("app/a.py", "x = 1\n" + LEAK)
    repo.git("add", "app/a.py")
    assert ss.scan_blob("app/a.py", (repo.path / "app/a.py").read_bytes(), publish=False,
                        local=None, only_lines=None)  # None = whole file


def test_plus_plus_line_does_not_hide_a_secret_from_the_commit_or_the_push(make_repo):
    repo = make_repo()
    text = "Notes\n++ counter bumped\n" + LEAK
    repo.write("app/notes.py", text)
    repo.git("add", "app/notes.py")
    proc = repo.scan("--staged")
    assert proc.returncode == 1 and "app/notes.py:3: [github-token]" in proc.stdout
    repo.git("commit", "-q", "-m", "notes")
    proc = repo.scan("--range", "HEAD")
    assert proc.returncode == 1 and "app/notes.py:3: [github-token]" in proc.stdout


@pytest.mark.parametrize("config", [
    ("diff.mnemonicPrefix", "true"),
    ("diff.noprefix", "true"),
    ("diff.srcPrefix", "x/"),
    ("diff.dstPrefix", "y/"),
])
def test_staged_mode_ignores_the_users_diff_prefix_config(make_repo, config):
    repo = make_repo()
    repo.git("config", *config)
    repo.write("app/settings.py", "DEBUG = False\n" + LEAK)
    repo.git("add", "app/settings.py")
    proc = repo.scan("--staged")
    assert proc.returncode == 1 and "app/settings.py:2: [github-token]" in proc.stdout


def test_staged_mode_ignores_a_textconv_driver(make_repo):
    repo = make_repo()
    repo.write(".gitattributes", "*.py diff=shout\n")
    repo.git("config", "diff.shout.textconv", "tr a-z A-Z")
    repo.write("app/settings.py", "DEBUG = False\n" + LEAK)
    repo.git("add", "-A")
    proc = repo.scan("--staged")
    assert proc.returncode == 1 and "app/settings.py:2: [github-token]" in proc.stdout


# --------------------------------------------------------------------------- #
# UTF-16 and other NUL-carrying files (finding 4)
# --------------------------------------------------------------------------- #

def _ps1_text() -> str:
    return ("# notes for Zebra Clinic\n$Server = 'ZEBRA-DC01'\n"
            f"$Password = '{fakes.rand('rt-ps1', 20)}'\n$Token = '{TOKEN}'\n"
            f"$Gateway = '{fakes.ip(10, 20, 30, 1)}'\n")


@pytest.mark.parametrize("encode", [
    lambda t: b"\xff\xfe" + t.encode("utf-16-le"),
    lambda t: b"\xfe\xff" + t.encode("utf-16-be"),
    lambda t: t.encode("utf-16-le"),  # no BOM: NUL-interleaved ASCII
    lambda t: b"\xff\xfe\x00\x00" + t.encode("utf-32-le"),
])
def test_utf16_and_utf32_text_is_decoded_and_scanned(tmp_path, encode):
    block = tmp_path / "local-block"
    block.write_text("Zebra Clinic\nZEBRA-DC01\n")
    found = ss.scan_blob("ops/notes.ps1", encode(_ps1_text()), publish=True,
                         local=ss.load_local_block(block))
    names = _detectors(found)
    assert "github-token" in names and "secret-assignment" in names
    assert names.count("local-block") == 2 and "ip-private" in names


def test_utf16_file_is_caught_on_commit_and_on_push(make_repo):
    repo = make_repo()
    (repo.path / "ops").mkdir()
    (repo.path / "ops" / "notes.ps1").write_bytes(b"\xff\xfe" + _ps1_text().encode("utf-16-le"))
    repo.git("add", "ops/notes.ps1")
    assert "[github-token]" in repo.scan("--staged").stdout
    repo.git("commit", "-q", "-m", "ps1")
    assert "[github-token]" in repo.scan("--range", "HEAD").stdout


def test_binary_content_is_searched_for_terms_and_shapes(tmp_path):
    block = tmp_path / "local-block"
    block.write_text("Zebra Clinic\n")
    blob = b"\x89PNG\r\n\x1a\n\x00\x00" + "Zebra Clinic".encode("utf-16-le") + b"\x00\x01" + LEAK.encode()
    names = _detectors(ss.scan_blob("img/logo.png", blob, publish=False, local=ss.load_local_block(block)))
    assert "local-block" in names and "github-token" in names


def test_publish_refuses_binary_that_is_not_an_image_or_a_font():
    data = b"\x7fELF\x02\x01\x01\x00" + bytes(range(256))
    assert "binary-file" in _detectors(ss.scan_blob("tools/agent.bin", data, publish=True, local=None))
    assert "binary-file" in _detectors(ss.scan_blob("docs/review.pdf", data, publish=True, local=None))
    assert ss.scan_blob("tools/agent.bin", data, publish=False, local=None) == []
    assert ss.scan_blob("img/logo.png", b"\x89PNG\r\n\x1a\n" + bytes(range(256)),
                        publish=True, local=None) == []


# --------------------------------------------------------------------------- #
# Allow markers (finding 5)
# --------------------------------------------------------------------------- #

def _fixture_case() -> str:
    return ('CASE = {"host": "' + fakes.ip(10, 44, 12, 7) + '", "contact": "jane.doe@'
            + 'clientcorp.com", "path": "/ho' + 'me/alice/x"}\n')


def test_a_bare_marker_never_allows_publish_only_detectors():
    text = f"# {MARK} fixture values for the parser test\n" + _fixture_case()
    names = _detectors(ss.scan_text("tests/test_x.py", text, publish=True))
    assert {"ip-private", "email-address", "home-path"} <= set(names)
    assert ss.scan_text("tests/test_x.py", text) == []  # nothing secret in it


def test_a_scoped_marker_allows_exactly_the_named_detectors():
    scoped = f"# {MARK}[ip-private,email-address] documentation host and contact\n"
    names = _detectors(ss.scan_text("tests/test_x.py", scoped + _fixture_case(), publish=True))
    assert names == ["home-path"]
    secret = f"x = 1  # {MARK}[ip-private] wrong scope\nclient_secret = '{fakes.rand('rt-scope', 32)}'\n"
    assert "secret-assignment" in _detectors(ss.scan_text("app/x.py", secret))


def test_a_scope_must_name_real_detectors():
    text = f"key = 1  # {MARK}[no-such-detector] because\n"
    assert _detectors(ss.scan_text("app/x.py", text)) == ["allow-marker-invalid"]


def test_the_reason_is_the_comment_not_the_code_after_it():
    value = fakes.rand("rt-js", 28)
    text = f'/* {MARK} */ const apiKey = "{value}";\n'
    names = _detectors(ss.scan_text("web/x.js", text))
    assert "allow-marker-without-reason" in names and "secret-assignment" in names
    ok = f'/* {MARK} generated in the test */ const apiKey = "{value}";\n'
    assert ss.scan_text("web/x.js", ok) == []


@pytest.mark.parametrize("opening, closing", [
    ("<!--", "-->"), ("<!--", "--!>"),      # "--!>" ends an HTML comment too
    ("<!--", "--!>\n"), ("{{!--", "--}}"), ("{{!", "}}"), ("<%#", "%>"), ("{#", "#}"),
    ("{%", "%}"), ("{*", "*}"), ("{/*", "*/}"),
])
def test_the_reason_is_the_comment_whatever_form_ends_it(opening, closing):
    """CodeQL py/bad-tag-filter: a comment end the scanner did not know made
    the code after the comment count as the marker's reason."""
    value = fakes.rand("rt-comment-end", 28)
    code = f'const apiKey = "{value}";'
    for path in ("web/x.html", "docs/x.md", "web/x.tsx"):
        bare = f"{opening} {MARK} {closing} {code}\n"
        names = _detectors(ss.scan_text(path, bare))
        assert "allow-marker-without-reason" in names and "secret-assignment" in names, (path, bare)
        ok = f"{opening} {MARK} generated in the test {closing} {code}\n"
        if not closing.endswith("\n"):
            assert ss.scan_text(path, ok) == [], (path, ok)


def test_a_reason_is_cut_at_the_first_comment_end():
    # No comment end has a letter, so the regex's re.I changes nothing today.
    assert ss._marker_reason(" fixture value --!> const apiKey = 1") == "fixture value"
    assert ss._marker_reason(" fixture value --> x") == "fixture value"
    assert ss._marker_reason(": -- fixture -- value -- ") == "fixture -- value"
    assert ss._marker_reason(" fixture value -- !> x") == "fixture value -- !> x"  # not an end


def test_an_old_marker_does_not_approve_a_new_value_below_it(make_repo):
    repo = make_repo()
    marker = f"# {MARK} fixture value for the vault test\n"
    repo.commit("tests/test_vault.py", marker + "DATTO_API_SECRET_KEY = 'fixture-value'\nx = 1\n")
    real = fakes.rand("rt-old-marker", 32)
    repo.write("tests/test_vault.py", marker + f"DATTO_API_SECRET_KEY = '{real}'\nx = 1\n")
    repo.git("add", "-A")
    proc = repo.scan("--staged")
    assert proc.returncode == 1 and "tests/test_vault.py:2: [vendor-credential]" in proc.stdout
    # re-affirming the marker in the same change allows it; --tree reads markers as they stand
    repo.write("tests/test_vault.py", marker.replace("vault test", "vault test, re-checked")
               + f"DATTO_API_SECRET_KEY = '{real}'\nx = 1\n")
    repo.git("add", "-A")
    assert repo.scan("--staged").returncode == 0
    assert repo.scan("--tree").returncode == 0


# --------------------------------------------------------------------------- #
# Commit and tag messages (finding 7)
# --------------------------------------------------------------------------- #

def test_range_mode_scans_commit_messages(make_repo, tmp_path):
    repo = make_repo()
    repo.commit("a.py", "x = 1\n", message=f"rotate token; old one was {TOKEN}")
    proc = repo.scan("--range", "HEAD")
    assert proc.returncode == 1 and "<commit-message>:1: [github-token]" in proc.stdout
    assert TOKEN not in proc.stdout
    block = tmp_path / "local-block"
    block.write_text("Zebra Clinic\n")
    repo.commit("b.py", "y = 2\n", message="fix the Zebra Clinic import")
    proc = repo.scan("--range", "HEAD~1..HEAD", "--local-block", str(block))
    assert proc.returncode == 1 and "<commit-message>:1: [local-block]" in proc.stdout


def test_the_session_trailer_on_agent_commits_passes(make_repo):
    repo = make_repo()
    message = ("feat: something\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n"
               "Claude-Session: https://claude.ai/code/session_" + fakes.rand("rt-trailer", 24) + "\n")
    repo.commit("a.py", "x = 1\n", message=message)
    assert repo.scan("--range", "HEAD").returncode == 0


def test_range_mode_scans_an_annotated_tag_message(make_repo):
    repo = make_repo()
    repo.commit("a.py", "x = 1\n")
    repo.git("tag", "-a", "v1", "-m", f"release; deploy key {TOKEN}")
    tag = repo.git("rev-parse", "v1").stdout.strip()
    proc = repo.scan("--range", tag)
    assert proc.returncode == 1 and "<tag-message>:1: [github-token]" in proc.stdout


def test_message_mode_reads_what_the_commit_will_keep(tmp_path):
    msg = tmp_path / "COMMIT_EDITMSG"
    scissors = ("# ------------------------ >8 ------------------------\n"
                "# Do not modify or remove the line above.\n# Everything below it will be ignored.\n")
    msg.write_text("fix the importer\n\n# Please enter the commit message\n" + scissors
                   + "diff --git a/x b/x\n+" + LEAK)
    run = [sys.executable, str(SCANNER), "--no-local-block", "--message", str(msg)]
    assert subprocess.run(run, capture_output=True).returncode == 0  # the diff below git's >8 is dropped
    # the cut line alone (typed, or pasted from another message) is not git's: git keeps what follows
    msg.write_text("fix the importer\n\n" + scissors.split("\n", 1)[0] + "\n" + LEAK)
    assert subprocess.run(run, capture_output=True).returncode == 1
    msg.write_text(f"fix the importer\n\ntoken was {TOKEN}\n")
    proc = subprocess.run(run, capture_output=True, text=True)
    assert proc.returncode == 1 and "<commit-message>:3: [github-token]" in proc.stdout


# --------------------------------------------------------------------------- #
# Secrets in file names (finding 12)
# --------------------------------------------------------------------------- #

def test_a_secret_in_a_path_is_a_finding(make_repo):
    path = f"apps/octo/adapters/tokens/{TOKEN}.txt"
    assert "path:github-token" in _detectors(ss.path_findings(path, b"", None))
    repo = make_repo()
    repo.write(path, "nothing here\n")
    repo.git("add", "-A")
    proc = repo.scan("--staged")
    assert proc.returncode == 1 and "[path:github-token]" in proc.stdout and TOKEN not in proc.stdout
    assert "path:ip-private" in _detectors(ss.path_findings("docs/" + fakes.ip(10, 1, 2, 3) + ".md",
                                                            b"", None, publish=True))
