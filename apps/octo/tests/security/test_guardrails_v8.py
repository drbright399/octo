"""Guardrails v8 (review round 5 of 2026-10-16, the final round): what the
v7 detectors, scanner and hooks still got wrong.

* runs of candidates in one token: redaction of job output went quadratic
  (a bare value scrubbed to the end of its word, the next candidate searched
  inside it again; an unbounded --key= / --password= value refused by its
  check and searched again one character later), and so did scanning
  (slack-token / whsec_ starting inside their own value, --password= runs);
  the JWT-prefix test, private-key redaction and the scissors search had
  costly constants or quadratic corners (hostile.py covers these runs now);
* a file name that is not UTF-8 skipped its content in pre-commit, pre-push
  and --tree (blobs are read by object id; an unreadable one is a finding);
  printing such a name crashed the report;
* commit-msg: the comment string comes from git's configuration; a block
  that only comment lines follow cuts only with commit.cleanup=scissors;
* excerpts: a password with a quote inside, or a short value after
  ``name=``, was printed in readable pieces.

Every value is built at run time, so this file passes the scanner it tests."""
from __future__ import annotations

import base64
import importlib.util
import itertools
import os
import random
import string
import subprocess
import sys
import time
from pathlib import Path

import pytest

from apps.octo.adapters.datto.job_output import normalize_job_output
from apps.octo.security import secret_patterns as sp
from apps.octo.tests.security import fakes, hostile
from apps.octo.tests.security.conftest import SCANNER

_SPEC = importlib.util.spec_from_file_location("scan_sensitive", SCANNER)
ss = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("scan_sensitive", ss)  # dataclasses resolve their module by name
_SPEC.loader.exec_module(ss)

LAN = fakes.ip(10, 20, 30, 40)
PW = "Xk9" + fakes.rand("v8-pw", 9) + "#2q"
PW8 = "Xk9" + fakes.rand("v8-pw8", 5)
BAD_NAME = os.fsdecode(b"n\xffe.txt")  # not UTF-8: a CP1252 / CP437 name from a Windows zip
SHOWN_NAME = "n�e.txt"


def _cpu(fn, *args) -> float:
    start = time.process_time()
    fn(*args)
    return time.process_time() - start


def _names(text: str, *, publish: bool = False) -> set[str]:
    return {h.detector for h in sp.find_hits(text, publish=publish)}


def _render(findings) -> str:
    return "\n".join(f.render() for f in findings)


def _no_piece(secret: str, text: str, n: int = 6) -> bool:
    return not any(secret[i:i + n] in text for i in range(len(secret) - n + 1))


def _fill(unit: str, size: int) -> str:
    return (unit * (size // len(unit) + 1))[:size]


def test_the_version_is_at_least_8():
    assert ss.GUARDRAILS_VERSION >= 8  # test_guardrails_v9 pins the current one


# --------------------------------------------------------------------------- #
# Runs of candidates: linear in redaction (job output) and in scanning
# --------------------------------------------------------------------------- #

# The reviewer's repros: one 400 kB stdout each (one job-output stream's cap).
# Before: 54 s, 22 s, 12 s, 11 s and 11 s of CPU.
_JOB_RUNS = {
    "key-option-path": "--key=/",
    "vendor-name-drive": "DATTO_API_KEY=C:" + "\\&",
    "key-name-placeholder": "ORG_KEY=example)",
    "password-option-marker": "--password=[REDACTED:x]",
    "accepted-bare-values": "pass" + "word=" + PW8 + ";",
}


@pytest.mark.parametrize("unit", list(_JOB_RUNS.values()), ids=list(_JOB_RUNS))
def test_runs_of_candidates_in_job_output_redact_in_linear_time(unit):
    text = _fill(unit, hostile.JOB)
    assert _cpu(sp.redact, text) < hostile.budget(text)
    assert _cpu(normalize_job_output, {"stdout": text, "stderr": "", "exit": 0}) < hostile.budget(text)


@pytest.mark.parametrize("template", [
    "agent.exe --password={v} --site x",
    "agent.exe --key {v} /q",
    "setup.exe /ACCT_KEY={v} /q",
    "install.sh --license-key={v}",
])
def test_a_value_longer_than_the_pattern_bound_is_still_redacted_whole(template):
    long = fakes.rand("v8-long", 600)
    out, n = sp.redact(template.replace("{v}", long))
    assert n >= 1 and _no_piece(long, out, 8), out[:200]


def test_bare_values_are_still_scrubbed_to_the_next_blank():
    out, n = sp.redact(f"password={PW}&next={PW8} tail\nORG_KEY={PW};x={PW8} end")
    assert n == 2 and PW not in out and PW8 not in out
    assert out.endswith(" end") and " tail\n" in out


def test_option_values_are_still_found_and_judged():
    assert "cli-secret-flag" in _names(f"tool --password={PW} --x")
    assert "cli-secret-flag" in _names(f"agent --token {PW}")
    assert "cli-secret-flag" not in _names("tool --password=--password=--password=")


def _slack() -> str:
    digits = "0123456789"
    return ("xox" + "b-" + fakes.rand("v8-sd1", 12, digits) + "-" + fakes.rand("v8-sd2", 12, digits)
            + "-" + fakes.rand("v8-slack", 24))


def _whsec() -> str:
    return "whs" + "ec_" + base64.b64encode(fakes.key_bytes("v8-whsec", 24)).decode()


# Before: 17 s at 40 kB, 23 s at 78 kB and 24 s at 88 kB (quadratic).
_SCAN_RUNS = {
    "slack-prefixes": ("xox" + "b-") * 16_000 + "example",
    "whsec-dash-joined": ("whs" + "ec_" + "Xk9mQ2pL" * 4 + "-") * 2_000 + "example",
    "password-options": "--password=" * 8_000,
    "key-options": "--key=" * 15_000,
}


@pytest.mark.parametrize("text", list(_SCAN_RUNS.values()), ids=list(_SCAN_RUNS))
def test_runs_of_rejected_candidates_scan_in_linear_time(text):
    assert _cpu(lambda: sp.find_hits(text, publish=True)) < hostile.budget(text)


def test_token_shapes_after_a_name_are_still_found():
    assert "slack-token" in _names(f"SLACK={_slack()}") and "slack-token" in _names(f"x {_slack()}")
    secret = _whsec()
    assert "webhook-signing-secret" in _names(f"SECRET={secret}")
    assert "webhook-signing-secret" in _names(f'"{secret}"')
    # joined to a value character it is a piece of a longer token (still found as one)
    # Bounded value instead of a narrowed lookbehind: still a signing secret after "-".
    assert "webhook-signing-secret" in _names(f"x-{secret}")


def test_the_jwt_prefix_test_has_one_start_per_token():
    # Before: 2.2 s at 61 kB (every "eyJ" in the 4 kB window was a start).
    rng = random.Random("v8-jwt-window")
    tokens = " ".join("".join(rng.choice(string.ascii_letters + string.digits) for _ in range(40))
                      for _ in range(90))
    text = ("eyJ" * 1300 + " " + tokens + " ") * 8
    assert _cpu(lambda: sp.find_hits(text, publish=True)) < hostile.budget(text)


def test_a_flood_of_private_key_headers_redacts_fast():
    # Before: 1.6 s for 400 kB (linear, 16 000 steps per header): now the
    # search for END stops at the next BEGIN. A quarter of the budget.
    text = _fill("-----BEGIN " + "PRIVATE KEY-----\n/\n", hostile.JOB)
    assert _cpu(normalize_job_output, {"stdout": text, "stderr": "", "exit": 0}) < hostile.budget(text) / 4


def test_a_private_key_block_is_still_redacted_whole():
    body = "\n".join(fakes.rand(f"v8-pem-{i}", 64) for i in range(6))
    key = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
    out, n = sp.redact(f"before\n{key}\nafter")
    assert n == 1 and out == "before\n[REDACTED:private-key]\nafter"
    # with no END line: the header and the base64 lines under it
    out, n = sp.redact(f"-----BEGIN PRIVATE KEY-----\n{body}\n")
    assert n == 1 and _no_piece(body.replace("\n", ""), out.replace("\n", ""), 12)


def test_hostile_runs_cover_the_reviewers_shapes():
    heads = {h for d in sp.DETECTORS for h in hostile.heads(d)}
    assert {"xox" + "b-", "xox" + "o-"} & heads and "whs" + "ec_" in heads
    labels = [label for label, _ in hostile.pipeline_inputs()]
    for head in ("--key=", "--password=", "DATTO_API_KEY=", "ORG_KEY=", "password="):
        assert any(label.startswith(f"{head}:rejected") for label in labels), head
    assert {"pem-headers", "jwt-prefix-window"} <= set(labels)


# --------------------------------------------------------------------------- #
# The scissors search: O(distance) per block
# --------------------------------------------------------------------------- #

_BLOCK = ("{c} ------------------------ >8 ------------------------\n"
          "{c} Do not modify or remove the line above.\n"
          "{c} Everything below it will be ignored.\n")
_HINT = ("{c} Please enter the commit message for your changes. Lines starting\n"
         "{c} with '{c}' will be ignored, and an empty message aborts the commit.\n")
_KEEP = ("{c} Please enter the commit message for your changes. Lines starting\n"
         "{c} with '{c}' will be kept; you may remove them yourself if you want to.\n"
         "{c} An empty message aborts the commit.\n")
_DIFF = "diff --git a/a b/a\nindex 1..2 100644\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-gw {lan}\n+gw 192.0.2.10\n"


@pytest.mark.parametrize("config", [ss.MessageConfig(), ss.MessageConfig(cleanup="scissors")])
@pytest.mark.parametrize("tail", ["x\n", "#\n", ""])
def test_many_pasted_scissors_blocks_stay_linear(config, tail):
    # Before: 9.5 s for 16 000 blocks (2.2 MB): each block split the rest of the message.
    raw = "subject\n" + (_BLOCK.format(c="#") + tail) * 16_000
    assert _cpu(lambda: ss.message_file_text(raw, editor=True, config=config)) < hostile.budget(raw)


def test_the_first_block_git_honours_is_still_the_cut():
    raw = ("subject\n" + _BLOCK.format(c="#") + f"host {LAN}\n" + _HINT.format(c="#") + "#\n"
           + _BLOCK.format(c="#") + _DIFF.replace("{lan}", LAN))
    kept = ss.message_file_text(raw, editor=True)
    assert f"host {LAN}" in kept and "diff --git" not in kept


# --------------------------------------------------------------------------- #
# commit-msg: git's comment string, git's cleanup
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw,config,kept", [
    # (c2) a block on another comment string is no block of git's
    ("subject\n\n" + _HINT.format(c="#") + _BLOCK.format(c="//") + "// host {lan}\n", None, True),
    # (d) neither is a hint on another string
    ("subject\n\n" + _HINT.format(c="#") + _HINT.format(c="//") + "// host {lan}\n", None, True),
    # (e) a '#' block that only '#' lines follow, under cleanup=whitespace (git's keep hint)
    (_BLOCK.format(c="#") + "# host {lan}\nsubject\n\n" + _KEEP.format(c="#"), None, True),
    # ... and under the default cleanup without -v: the block is not git's, the hint strips
    (_BLOCK.format(c="#") + "# host {lan}\nsubject\n\n" + _HINT.format(c="#"), None, False),
    # core.commentString=// (git 2.45+): its hint and block count
    ("subject\n\n" + _HINT.format(c="//") + "// host {lan}\n", ss.MessageConfig(("//",)), False),
    ("subject\n\n" + _BLOCK.format(c="//") + _DIFF, ss.MessageConfig(("//",)), False),
    # core.commentChar=auto: one of git's candidates
    ("subject\n\n" + _HINT.format(c="@") + "@ host {lan}\n", ss.MessageConfig(tuple("#;@!$%^&|:")), False),
    ("subject\n\n" + _HINT.format(c="~") + "~ host {lan}\n", ss.MessageConfig(tuple("#;@!$%^&|:")), True),
    # commit.cleanup=whitespace / verbatim in git's configuration: nothing is stripped
    ("subject\n\n" + _HINT.format(c="#") + "# host {lan}\n", ss.MessageConfig(cleanup="whitespace"), True),
    ("subject\n\n" + _HINT.format(c="#") + "# host {lan}\n", ss.MessageConfig(cleanup="verbatim"), True),
    # a strip hint typed above git's keep hint (--cleanup=whitespace on the command line)
    ("subject\n" + _HINT.format(c="#") + "# host {lan}\n\n" + _KEEP.format(c="#"), None, True),
])
def test_only_gits_own_comment_string_and_cleanup_count(raw, config, kept):
    raw = raw.replace("{lan}", LAN)
    text = ss.message_file_text(raw, editor=True, config=config or ss.MessageConfig())
    assert (LAN in text) is kept


def _git_env(repo, **config: str) -> dict[str, str]:
    env = dict(repo.env, LC_ALL="C")
    for i, (key, value) in enumerate(config.items()):
        env[f"GIT_CONFIG_KEY_{i}"] = key.replace("__", ".")
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    if config:
        env["GIT_CONFIG_COUNT"] = str(len(config))
    return env


def test_message_config_reads_gits_configuration(make_repo):
    repo = make_repo()
    assert ss.message_config(repo.path) == ss.MessageConfig(("#",), "")
    repo.git("config", "core.commentChar", ";")
    repo.git("config", "commit.cleanup", "Scissors")
    assert ss.message_config(repo.path) == ss.MessageConfig((";",), "scissors")
    repo.git("config", "core.commentChar", "auto")
    assert set(ss.message_config(repo.path).comments) == set("#;@!$%^&|:")


@pytest.fixture
def guarded(make_repo):
    """A clone with the guardrails installed and committed, and a bare remote."""
    remote = make_repo("remote.git", bare=True)
    repo = make_repo()
    repo.install_guardrails()
    repo.git("add", "-A")
    first = repo.git("commit", "-q", "-m", "guardrails", check=False)
    assert first.returncode == 0, first.stdout + first.stderr
    repo.git("remote", "add", "origin", str(remote.path))
    return repo, remote


def _editor(tmp_path: Path, *, prepend: str = "", append: str = "") -> Path:
    """GIT_EDITOR: text before and after git's template."""
    (tmp_path / "before.txt").write_text(prepend)
    (tmp_path / "after.txt").write_text(append)
    script = tmp_path / "editor.sh"
    script.write_text(f'#!/bin/sh\ncat "{tmp_path}/before.txt" "$1" "{tmp_path}/after.txt" > "$1.new" '
                      '&& mv "$1.new" "$1"\n')
    script.chmod(0o755)
    return script


_COMMITS = itertools.count()


def _commit(repo, editor: Path, *args: str, **config: str) -> subprocess.CompletedProcess:
    repo.write("app/c.py", f"z = {next(_COMMITS)}\n")  # always something to commit
    repo.git("add", "app/c.py")
    env = dict(_git_env(repo, **config), GIT_EDITOR=str(editor))
    return subprocess.run(["git", "commit", "-q", *args], cwd=repo.path, env=env, capture_output=True, text=True)


@pytest.mark.parametrize("prepend,append,args", [
    ("subject\n", "// ------------------------ >8 ------------------------\n"
     "// Do not modify or remove the line above.\n// Everything below it will be ignored.\n// host {lan}\n", ()),
    ("subject\n", "// Please enter the commit message for your changes. Lines starting\n"
     "// with '//' will be ignored, and an empty message aborts the commit.\n// host {lan}\n", ()),
    (_BLOCK.format(c="#") + "# host {lan}\nsubject\n", "", ("--cleanup=whitespace",)),
], ids=["c2-scissors-on-another-string", "d-hint-on-another-string", "e-block-under-cleanup-whitespace"])
def test_commit_msg_refuses_what_git_keeps(guarded, tmp_path, prepend, append, args):
    repo, _ = guarded
    editor = _editor(tmp_path, prepend=prepend.replace("{lan}", LAN), append=append.replace("{lan}", LAN))
    proc = _commit(repo, editor, *args)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "[ip-private]" in out and LAN not in out
    assert repo.git("log", "-1", "--format=%s").stdout.strip() == "guardrails"


def test_commit_msg_follows_a_configured_comment_char(guarded, tmp_path):
    repo, _ = guarded
    # git -c core.commentChar=';': git strips the ';' lines, so the hook does too
    editor = _editor(tmp_path, prepend="subject\n", append=f"; host {LAN}\n")
    proc = _commit(repo, editor, core__commentChar=";")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    message = repo.git("log", "-1", "--format=%B").stdout
    assert message.startswith("subject") and LAN not in message


def test_commit_msg_follows_cleanup_scissors(guarded, tmp_path):
    repo, _ = guarded
    (repo.path / f"gw-{LAN}.txt").write_text("untracked: listed under git's scissors block\n")
    editor = _editor(tmp_path, prepend="subject\n")
    proc = _commit(repo, editor, commit__cleanup="scissors")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    message = repo.git("log", "-1", "--format=%B").stdout
    assert message.startswith("subject") and LAN not in message
    # without that setting git keeps comment lines under a typed block: refused
    proc = _commit(repo, _editor(tmp_path, prepend="subject\n" + _BLOCK.format(c="#") + f"# gw {LAN}\n"),
                   "--cleanup=whitespace")
    assert proc.returncode != 0 and "[ip-private]" in proc.stdout + proc.stderr


# --------------------------------------------------------------------------- #
# File names that are not UTF-8: read by object id, printed safely
# --------------------------------------------------------------------------- #

def _run(args, cwd, env=None) -> tuple[int, str]:
    """A command's exit code and output; the output must be valid UTF-8 (a
    raw non-UTF-8 name never reaches it) and carry no traceback."""
    proc = subprocess.run(args, cwd=cwd, env=env, capture_output=True)
    out = (proc.stdout + proc.stderr).decode("utf-8")  # strict: fails on a raw 0xFF
    assert "Traceback" not in out, out
    return proc.returncode, out


def _add_bad_name(repo) -> None:
    (repo.path / BAD_NAME).write_bytes(f"gw {LAN}\n".encode())
    assert subprocess.run(["git", "add", "-A"], cwd=repo.path, env=repo.env).returncode == 0


def test_pre_commit_checks_a_file_whose_name_is_not_utf8(guarded):
    repo, _ = guarded
    _add_bad_name(repo)
    rc, out = _run(["git", "commit", "-q", "-m", "add"], repo.path, repo.env)
    assert rc != 0 and f"{SHOWN_NAME}:1: [ip-private]" in out and LAN not in out


def test_pre_push_checks_a_file_whose_name_is_not_utf8(guarded):
    repo, remote = guarded
    _add_bad_name(repo)
    assert subprocess.run(["git", "commit", "-q", "--no-verify", "-m", "add"], cwd=repo.path,
                          env=repo.env).returncode == 0
    rc, out = _run(["git", "push", "origin", "main"], repo.path, repo.env)
    assert rc != 0 and f"{SHOWN_NAME}:1: [ip-private]" in out and LAN not in out
    assert remote.git("rev-parse", "--verify", "-q", "refs/heads/main", check=False).returncode != 0


def test_the_tree_scan_reads_a_file_whose_name_is_not_utf8(make_repo, tmp_path):
    repo = make_repo()
    _add_bad_name(repo)
    rc, out = _run([sys.executable, str(SCANNER), "--tree", "--publish", "--root", str(repo.path),
                    "--no-local-block"], repo.path)
    assert rc == 1 and f"{SHOWN_NAME}:1: [ip-private]" in out and LAN not in out
    # outside git (os.walk): the same, and the report prints
    plain = tmp_path / "export"
    plain.mkdir()
    (plain / BAD_NAME).write_bytes(f"gw {LAN}\n".encode())
    rc, out = _run([sys.executable, str(SCANNER), "--tree", "--publish", "--root", str(plain),
                    "--no-local-block"], tmp_path)
    assert rc == 1 and f"{SHOWN_NAME}:1: [ip-private]" in out and LAN not in out


def test_a_ref_name_that_is_not_utf8_prints(tmp_path):
    name = b"refs/heads/\xff" + LAN.encode()
    rc, out = _run([sys.executable, str(SCANNER).encode(), b"--ref-name", name, b"--publish",
                    b"--no-local-block"], tmp_path)
    assert rc == 1 and "[ref:ip-private]" in out and "refs/heads/�" in out and LAN not in out


def test_paths_from_git_are_kept_byte_for_byte():
    assert ss._unquote('"a\\tb\\"c\\303\\251.txt"') == 'a\tb"cé.txt'
    assert ss._unquote('"x\\377y z"') == os.fsdecode(b"x\xffy z")
    raw = os.fsdecode(b"+++ b/n\xffe.txt")
    diff = f"diff --git a/x b/x\n--- /dev/null\n{raw}\n@@ -0,0 +1,2 @@\n+a\n+b\n"
    assert ss.added_lines(diff) == {BAD_NAME: {1, 2}}


class _Reader:
    """A blob reader that can produce nothing (a missing object)."""

    def read(self, spec: str):
        return None


def test_an_added_blob_that_cannot_be_read_is_a_finding():
    found = ss._scan_change(_Reader(), f"docs/{LAN}.md", "100644", "ab" * 20, publish=True, local=None,
                            only_lines=None)
    assert {f.detector for f in found} == {ss.UNREADABLE, "path:ip-private"}
    assert LAN not in _render(found)
    # a gitlink names a commit of another repository: no content, no finding
    assert ss._scan_change(_Reader(), "vendor/lib", "160000", "cd" * 20, publish=True, local=None,
                           only_lines=None) == []


def test_raw_diff_records_are_parsed_strictly():
    sha = "0123456789abcdef" * 2 + "01234567"
    raw = f":000000 100644 {'0' * 40} {sha} A\0{BAD_NAME}\0:100644 160000 {sha} {sha} T\0vendor/lib\0"
    assert ss._changed_blobs(raw) == [(BAD_NAME, "100644", sha), ("vendor/lib", "160000", sha)]
    with pytest.raises(ss.GitError):
        ss._changed_blobs(f"{BAD_NAME}\0")
    with pytest.raises(ss.GitError):
        ss._changed_blobs(f":100644 100644 {sha} {sha} M\0")


def test_a_staged_blob_git_cannot_read_refuses(make_repo):
    repo = make_repo()
    repo.git("update-index", "--add", "--cacheinfo", f"100644,{'12' * 20},app/x.py")
    proc = repo.scan("--staged", "--publish", "--no-local-block")
    assert proc.returncode == 2 and "Traceback" not in proc.stderr


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads any file")
def test_a_tree_file_that_cannot_be_read_is_a_finding(make_repo):
    repo = make_repo()
    locked = repo.write("docs/locked.md", "x\n")
    repo.write("docs/gone.md", "y\n")
    repo.git("add", "-A")
    (repo.path / "docs" / "gone.md").unlink()  # deleted, git knows: nothing to check
    locked.chmod(0)
    try:
        proc = repo.scan("--tree", "--publish", "--no-local-block")
    finally:
        locked.chmod(0o644)
    assert proc.returncode == 1 and "docs/locked.md:0: [unreadable-file]" in proc.stdout
    assert "gone.md" not in proc.stdout


def test_a_report_that_fails_is_exit_2_without_the_value(monkeypatch, capsys, tmp_path):
    (tmp_path / "net.md").write_text(f"gw {LAN}\n")

    def broken(findings, quiet):
        raise UnicodeEncodeError("utf-8", LAN, 0, 1, "surrogates not allowed")

    monkeypatch.setattr(ss, "_report", broken)
    monkeypatch.delenv(ss.DEBUG_ENV, raising=False)
    assert ss.main(["--tree", "--publish", "--root", str(tmp_path), "--no-local-block"]) == 2
    err = capsys.readouterr().err
    assert "internal error (UnicodeEncodeError)" in err and LAN not in err


# --------------------------------------------------------------------------- #
# Excerpts: quotes inside a word, short values after name=, wrappers
# --------------------------------------------------------------------------- #

def _excerpt_of(line: str) -> str:
    found = ss.scan_text("ops/hosts.txt", line + "\n", publish=True)
    assert "ip-private" in {f.detector for f in found}, line
    return _render(found)


@pytest.mark.parametrize("pw", [
    "Xk9m'Q2p!zR", 'yi)"0&S?4B', "Ab3`xY7#qz", "cRl@I5k'", "'+I7G}Nl", "#Z)8zS('*k", "88?M;'\"u3",
])
def test_a_password_with_a_quote_in_it_is_masked(pw):
    rendered = _excerpt_of(f"{LAN} admin {pw}")
    assert _no_piece(pw, rendered), rendered.replace(pw, "<pw>")


@pytest.mark.parametrize("word", [
    "aa=9#^aa$a", "pw=Xk9mQ2p", "x:Ab3!zz", "k=7#Qx_2v", "(Xk9mQ2p)", "[Xk9#mQ2]", "Xk9#mQ2,", "/pUmh;4L",
])
def test_a_short_value_after_a_name_or_inside_wrappers_is_masked(word):
    rendered = _excerpt_of(f"{LAN} {word}")
    assert _no_piece(word, rendered), rendered.replace(word, "<w>")


@pytest.mark.parametrize("readable", [
    "port=5432 mode=fast host=dc01 retries=3 lang=enUS",
    "don't shouldn't couldn't it's",
    '"admin","Example Corp",\'x\'',
    '{"user":"alice","role":"ops"}',
    'print("hello") foo(\'bar\') a["k"]',
    "(default) [dc01] (client-side) v1.2.3-rc.1",
])
def test_names_numbers_quotes_and_fields_stay_readable(readable):
    assert readable in _excerpt_of(f"{LAN} {readable}")


_FUZZ_SYMBOLS = "!#$%^&*()[]{}<>?~|=:/'\"`@,;.-_+"


def test_fuzz_quotes_and_name_prefixes_leave_no_six_character_piece():
    """The reviewer's shapes: a quote inside a password (300 of 300 printed
    before), a password that starts like ``x=`` / ``x:`` / ``/`` (about 4 %
    printed). Every password here is one of those shapes."""
    rng = random.Random("secret-guardrails:v8-quotes-and-prefixes")
    templates = ["{ip} admin {pw}", "{ip} {pw}", "{pw} {ip}", "{ip}\t{pw}"]
    core_chars = string.ascii_letters + string.digits + "!#$%^&*?~|@+"
    for i in range(900):
        body = [rng.choice(string.ascii_uppercase), rng.choice(string.digits), rng.choice("!#$%^&*?~")]
        body += [rng.choice(core_chars) for _ in range(rng.randint(4, 8))]
        rng.shuffle(body)
        kind = i % 3
        if kind == 0:  # a quote between two value characters
            at = rng.randint(1, len(body) - 1)
            pw = "".join(body[:at]) + rng.choice("'\"`") + "".join(body[at:])
        elif kind == 1:  # x= / x: / ab= then a short value (8+ in all) that is not letters alone
            name = "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(1, 3)))
            value = body[:max(5, 7 - len(name))]
            if "".join(value).isalpha():  # letters alone are read as words (documented)
                value[-1] = rng.choice(string.digits)
            pw = name + rng.choice("=:") + "".join(value)
        else:  # a path-like start (8+ in all)
            start = rng.choice(["/", "./", "~/"])
            pw = start + "".join(body[:rng.randint(8 - len(start), 9)])
        line = rng.choice(templates).replace("{ip}", LAN).replace("{pw}", pw)
        rendered = _render(ss.scan_text("ops/hosts.txt", line + "\n", publish=True))
        assert _no_piece(pw, rendered), (pw, rendered.replace(pw, "<pw>"))
