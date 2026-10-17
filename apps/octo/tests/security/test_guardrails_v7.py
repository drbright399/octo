"""Guardrails v7 (review round 4 of 2026-10-15, the convergence round): what
the v6 hooks and detectors still got wrong.

* ReDoS: docker / podman / nerdctl login's option list split each ``--x`` two
  ways (exponential); every detector, every program check and the
  whole pipeline are now timed on generated hostile lines (``hostile.py``);
* a check that raises (an IP written in Arabic-Indic digits) is no hit, not a
  crash and not a traceback with the value;
* excerpts: an 8-character password with punctuation at an edge, written as
  its own word, was printed in clear;
* pre-push: a clone that lacks the remote's newest tips fetches their objects
  (no refs) before it judges what the remote holds, and says to fetch when it
  cannot;
* cli-password: PowerShell / cmd expansions are no literal password;
* commit-msg: only git's own scissors block and strip hint are trusted.

Every value is built at run time, so this file passes the scanner it tests."""
from __future__ import annotations

import dataclasses
import importlib.util
import json
import os
import random
import re
import string
import subprocess
import sys
import time
from pathlib import Path

import pytest

from apps.octo.security import secret_patterns as sp
from apps.octo.tests.security import fakes, hostile
from apps.octo.tests.security.conftest import REPO_ROOT, SCANNER

_SPEC = importlib.util.spec_from_file_location("scan_sensitive", SCANNER)
ss = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("scan_sensitive", ss)  # dataclasses resolve their module by name
_SPEC.loader.exec_module(ss)

LAN = fakes.ip(10, 20, 30, 40)
PW = "Zq7" + fakes.rand("v7-pw", 7) + "#2w"
SECRET = fakes.rand("v7-secret", 32)


def _names(text: str, *, publish: bool = False) -> set[str]:
    return {h.detector for h in sp.find_hits(text, publish=publish)}


def _detectors(findings) -> list[str]:
    return [f.detector for f in findings]


def _render(findings) -> str:
    return "\n".join(f.render() for f in findings)


def _no_piece(secret: str, text: str, n: int = 6) -> bool:
    return not any(secret[i:i + n] in text for i in range(len(secret) - n + 1))


# --------------------------------------------------------------------------- #
# ReDoS: docker login, and every detector on hostile input
# --------------------------------------------------------------------------- #

def _cpu(fn, *args) -> float:
    start = time.process_time()
    fn(*args)
    return time.process_time() - start


@pytest.mark.parametrize("k", [16, 22, 40, 140])
def test_the_docker_login_option_list_is_linear(k):
    from apps.octo.adapters.datto.job_output import normalize_job_output

    # Before: 4 times slower for every 2 options (k=22: 2 s; k=40: days).
    text = "docker" + " --a" * k + " --loginx -p " + PW
    assert _cpu(sp.find_hits, text) < 0.5
    assert _cpu(lambda: sp.find_hits(text, publish=True)) < 0.5
    assert _cpu(sp.redact, text) < 0.5
    assert _cpu(normalize_job_output, {"stdout": text + "\n", "stderr": "", "exit": 0}) < 0.5


@pytest.mark.parametrize("prefix", [
    "docker login", "docker --debug login", "docker --log-level=debug login", "docker -D login",
    "docker.exe --tls --tlsverify login", "podman login", "nerdctl --namespace=k8s.io login",
])
def test_docker_login_forms_are_still_found(prefix):
    text = f"{prefix} -u admin -p {PW} registry.example.com"
    assert "cli-password" in _names(text), prefix
    out, n = sp.redact(text)
    assert n >= 1 and PW not in out


def test_more_than_twelve_global_options_before_login_are_not_followed():
    # The bound that keeps the option list linear; no real command line has 13.
    text = "docker" + " --a" * 13 + " login -p " + PW
    assert "cli-password" not in _names(text)


DEADLINE = 300  # seconds for the whole hostile run (about 25 s here)


@pytest.fixture(scope="module")
def hostile_run(tmp_path_factory):
    """``hostile.py`` in a subprocess (a catastrophic regex cannot be stopped
    in-process), killed at DEADLINE: what it printed, and how it ended."""
    out = tmp_path_factory.mktemp("hostile") / "calls.jsonl"
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT), PYTHONDONTWRITEBYTECODE="1")
    with out.open("w") as fh:
        proc = subprocess.Popen([sys.executable, "-m", "apps.octo.tests.security.hostile"],
                                stdout=fh, stderr=subprocess.PIPE, cwd=REPO_ROOT, env=env, text=True)
        try:
            _, err = proc.communicate(timeout=DEADLINE)
            stopped = False
        except subprocess.TimeoutExpired:
            proc.kill()
            _, err = proc.communicate()
            stopped = True
    rows = [json.loads(line) for line in out.read_text().splitlines() if line.strip()]
    return rows, stopped, err or ""


# v8: "job-output" = option / assignment runs through the whole pipeline, the
# heaviest at one job-output stream's cap (hostile.pipeline_inputs).
HOSTILE_TARGETS = ([d.name for d in sp.DETECTORS] + [name for name, _ in hostile.program_regexes(sp)]
                   + ["job-output"])


@pytest.mark.parametrize("target", HOSTILE_TARGETS)
def test_every_detector_and_program_check_stays_fast_on_hostile_input(hostile_run, target):
    """Each detector alone (pattern + check, scan and redact), each program
    check of the cli-password families, and find_hits / redact / the Datto
    job-output normaliser / the scanner's masked report (scan_text), on
    lines of 50 kB to 200 kB built from the
    detector's own needles, literals and sampled matches: repeated option
    tokens, long runs, near misses. Budget: 0.5 s of CPU per call per 50 kB
    (the worst today is about a tenth of that)."""
    rows, stopped, err = hostile_run
    mine = [r for r in rows if r.get("target") == target]
    assert mine, (f"{target} was never reached: the runner "
                  + ("hit its deadline earlier" if stopped else f"failed: {err[-800:]}"))
    started = {(r["input"], r["path"]) for r in mine if r.get("start")}
    finished = {(r["input"], r["path"]): r for r in mine if "seconds" in r}
    hung = sorted(started - set(finished))
    assert not hung, f"{target} did not finish (catastrophic backtracking?) on {hung[:3]}"
    slow = sorted(((r["seconds"], key) for key, r in finished.items()
                   if r["seconds"] > hostile.BUDGET * max(1.0, r["size"] / hostile.SIZE)), reverse=True)
    assert not slow, f"{target} over budget: {slow[:5]}"
    paths = {r["path"] for r in finished.values()}
    if target in {d.name for d in sp.DETECTORS}:
        assert {"detector:scan", "detector:redact", "find_hits", "redact", "normalize", "scan_text"} <= paths
        assert max(r["size"] for r in finished.values()) >= hostile.BIG
    elif target == "job-output":
        assert paths == {"find_hits", "redact", "normalize"}
        assert max(r["size"] for r in finished.values()) >= hostile.JOB
    else:
        assert paths == {"program"}


def test_the_hostile_runner_finished(hostile_run):
    rows, stopped, err = hostile_run
    assert not stopped and rows and rows[-1] == {"done": True}, err[-800:]


def test_hostile_lines_cover_option_lists_needles_and_sizes():
    spaced = next(d for d in sp.DETECTORS if d.name == "cli-password:spaced-p")
    texts = [t for _, t in hostile.detector_inputs(spaced)]
    assert any(t.count(" --a") >= 40 and "--loginx" in t for t in texts)  # the docker ReDoS shape
    assert max(len(t) for t in texts) >= hostile.SIZE
    for d in sp.DETECTORS:
        seeds = hostile.seeds_of(d)
        assert seeds and all(n in seeds for n in d.needles[:2] if len(n.strip()) >= 2), d.name


# --------------------------------------------------------------------------- #
# Crash safety: no check raises, no traceback prints a value
# --------------------------------------------------------------------------- #

ARABIC_INDIC = "\u0661\u0660.\u0662\u0660.\u0663\u0660.\u0664\u0660"
FULLWIDTH = "\uff11\uff10.\uff12\uff10.\uff13\uff10.\uff14\uff10"
UNICODE_IPS = [
    ARABIC_INDIC, FULLWIDTH, "\u0660.20.30.40", "\u0661\u0660.20.30.40", "x\u0661\u0660.20.30.40",
    "1\u0660.20.30.40", "10.20.30.\u0664\u0660", "\uff11\uff10.20.30.40",
]
_IP_NAMES = {"ip-private", "ip-public", "ip-tailnet"}


@pytest.mark.parametrize("weird", UNICODE_IPS)
def test_non_ascii_digits_never_crash_find_hits_scan_text_or_ref_names(weird):
    assert not _names(f"gw {weird}", publish=True) & _IP_NAMES
    found = ss.scan_text("docs/net.md", f"gw {weird}\n", publish=True)
    assert not set(_detectors(found)) & _IP_NAMES
    assert ss.scan_ref_name(f"refs/heads/fix-{weird}", local=None, publish=True) == []
    # an ASCII address on the same line is still found, and masked
    found = ss.scan_text("docs/net.md", f"gw {weird} and {LAN}\n", publish=True)
    assert _detectors(found) == ["ip-private"] and LAN not in _render(found)
    found = ss.scan_ref_name(f"refs/heads/{weird}-{LAN}", local=None, publish=True)
    assert _detectors(found) == ["ref:ip-private"] and LAN not in _render(found)


def test_an_ascii_address_with_a_non_ascii_prefix_length_is_still_an_address():
    found = ss.scan_text("docs/net.md", f"net {LAN}/\u0662\u0664\n", publish=True)
    assert _detectors(found) == ["ip-private"] and LAN not in _render(found)


def test_ip_kind_refuses_what_is_not_an_address():
    m = re.match(r"(?P<ip>.+?)(?P<cidr>)$", ARABIC_INDIC)
    assert sp._ip_kind(m.group("ip"), m, "scan", sp.Context()) is False


def test_a_check_that_raises_is_no_hit_scrubbed_in_redaction_and_a_masked_warning(monkeypatch, capsys):
    def boom(value, m, purpose, ctx):
        raise ValueError(f"cannot judge {value}")  # the message quotes the value

    target = next(d for d in sp.DETECTORS if d.name == "secret-assignment")
    monkeypatch.setattr(sp, "DETECTORS", tuple(dataclasses.replace(d, check=boom) if d is target else d
                                               for d in sp.DETECTORS))
    monkeypatch.setattr(sp, "_CHECK_FAILURES", set())
    text = f"client_secret = '{SECRET}'\ngw {LAN}\n"
    names = _names(text, publish=True)
    assert "secret-assignment" not in names and "ip-private" in names  # every other detector ran
    err = capsys.readouterr().err
    assert "secret-assignment" in err and "ValueError" in err and SECRET not in err
    out, n = sp.redact(text)  # redaction fails closed: the candidate is scrubbed
    assert n >= 1 and SECRET not in out
    err = capsys.readouterr().err
    assert "scrubbed" in err and SECRET not in err
    found = ss.scan_text("app/settings.py", text, publish=True)
    assert "ip-private" in _detectors(found) and SECRET not in _render(found)
    sp.find_hits(text)  # warned once per detector, purpose and exception type
    assert capsys.readouterr().err == ""


def test_the_scanner_cli_survives_non_ascii_digits(tmp_path):
    root = tmp_path / "export"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "net.md").write_text(f"gw {ARABIC_INDIC}\nalt {FULLWIDTH}\n", encoding="utf-8")
    args = [sys.executable, str(SCANNER), "--tree", "--publish", "--root", str(root), "--no-local-block"]
    proc = subprocess.run(args, capture_output=True, text=True)
    assert proc.returncode == 0 and "Traceback" not in proc.stderr, proc.stdout + proc.stderr
    (root / "docs" / "more.md").write_text(f"gw {ARABIC_INDIC} or {LAN}\n", encoding="utf-8")
    proc = subprocess.run(args, capture_output=True, text=True)
    assert proc.returncode == 1 and "Traceback" not in proc.stderr
    assert "docs/more.md:1: [ip-private]" in proc.stdout and LAN not in proc.stdout


def test_an_internal_error_is_exit_2_without_the_value(monkeypatch, capsys, tmp_path):
    def broken(*args, **kwargs):
        raise ValueError(f"unexpected {SECRET}")

    monkeypatch.setattr(ss, "scan_tree", broken)
    monkeypatch.delenv(ss.DEBUG_ENV, raising=False)
    argv = ["--tree", "--publish", "--root", str(tmp_path), "--no-local-block"]
    assert ss.main(argv) == 2
    err = capsys.readouterr().err
    assert "internal error (ValueError)" in err and SECRET not in err and "Traceback" not in err
    monkeypatch.setenv(ss.DEBUG_ENV, "1")
    with pytest.raises(ValueError):
        ss.main(argv)


# --------------------------------------------------------------------------- #
# Excerpts: a password written as its own word
# --------------------------------------------------------------------------- #

def _own_word_passwords() -> list[str]:
    return [
        "Ad" + "min12!",                     # the length-8 complexity minimum: Xxxxxx1!
        "Hq4#" + "zR8!",
        "*Hq4" + "zR8w",
        "Xk9m" + "Q2p!",
        "pSa>" + "\u00e7)XmG",                 # no digit, no "password symbol"
        "C(\u0416\u0416" + "joxB}",
        "!Wq3" + "rT8z",
        "Wq3r" + "T8z?",
        "~Wq3" + "rT8z~",
        "_Wq3" + "rT8z_",
    ]


_OWN_WORD = ["{ip} {pw}", "{ip} admin {pw}", '"{ip}","admin","{pw}"', "'{ip}','{pw}'",
             "{pw} {ip}", "net user localadmin {pw} /add # on {ip}", "{ip}\t{pw}\tadmin",
             "{ip} admin {pw}.", "{ip} admin {pw},", "{ip} ({pw})", "{ip} [{pw}]"]


@pytest.mark.parametrize("pw", _own_word_passwords())
@pytest.mark.parametrize("template", _OWN_WORD)
def test_a_password_as_its_own_word_is_masked(template, pw):
    line = template.replace("{ip}", LAN).replace("{pw}", pw)
    found = ss.scan_text("ops/hosts.csv", line + "\n", publish=True)
    rendered = _render(found)
    assert "ip-private" in _detectors(found) and LAN not in rendered
    assert pw not in rendered and _no_piece(pw, rendered), rendered.replace(pw, "<pw>")


def test_names_versions_dates_hosts_paths_and_options_stay_readable():
    text = (f"run scan_sensitive.py --tree --publish on {LAN} at 2026-10-15T10:00:00Z, release v1.2.3-rc.1\n"
            f"src/app.py (client-side) to rmm.vendor.invalid; {LAN} db.local:5432 Co-Authored-By: svc_backup\n"
            f"{LAN} ADAPTER_KEY_BASE64 default-dashboard.\n")
    found = ss.scan_text("ops/notes.md", text, publish=True)
    rendered = _render(found)
    assert _detectors(found) == ["ip-private"] * 3 and LAN not in rendered
    for readable in ("scan_sensitive.py", "--tree", "--publish", "2026-10-15T10:00:00Z", "v1.2.3-rc.1",
                     "src/app.py", "(client-side)", "rmm.vendor.invalid", "db.local:5432",
                     "Co-Authored-By:", "svc_backup", "ADAPTER_KEY_BASE64", "default-dashboard."):
        assert readable in rendered, readable


_FUZZ_SYMBOLS = "!#$%^&*()[]{}<>?~|"
_FUZZ_LETTERS = string.ascii_letters + "\u00e4\u00f6\u00fc\u00df\u00e9\u00f1\u00f8\u00c4\u00d6\u00dc\u00c9"


def _fuzz_password(rng: random.Random) -> str:
    """8 to 16 characters with an upper- and a lower-case letter, a digit and
    a symbol (no field separator, quote or blank: those split a word), whose
    core (prose punctuation and a wrapping pair aside) is still 8+."""
    while True:
        n = rng.randint(8, 16)
        chars = [rng.choice(string.ascii_uppercase), rng.choice(string.ascii_lowercase),
                 rng.choice(string.digits), rng.choice(_FUZZ_SYMBOLS)]
        chars += [rng.choice(_FUZZ_LETTERS + string.digits + _FUZZ_SYMBOLS) for _ in range(n - 4)]
        rng.shuffle(chars)
        pw = "".join(chars)
        if len(ss._prose_core(pw)) >= 8:
            return pw


def test_fuzz_no_six_character_piece_of_a_password_word_is_printed():
    rng = random.Random("secret-guardrails:v7-own-word")
    templates = ["{ip} {pw}", '"{ip}","{pw}"', "'{ip}','{pw}'", "{ip} admin {pw}", "{pw} {ip}",
                 '"{ip}","admin","{pw}"', "{ip}\t{pw}"]
    for _ in range(1500):
        pw = _fuzz_password(rng)
        template = rng.choice(templates)
        found = ss.scan_text("ops/hosts.csv", template.replace("{ip}", LAN).replace("{pw}", pw) + "\n",
                             publish=True)
        rendered = _render(found)
        assert "ip-private" in _detectors(found), template
        assert _no_piece(pw, rendered), (template, rendered.replace(pw, "<pw>"))


# --------------------------------------------------------------------------- #
# cli-password: what a shell expands is no literal password (scan only)
# --------------------------------------------------------------------------- #

CLI_EXPANSIONS = [
    'sqlcmd -S srv -U sa -P "$($cred.GetNetworkCredential().Password)"',
    "plink -pw $($cred.GetNetworkCredential().Password) alice@h",
    "sqlcmd -S srv -U sa -P (Get-Secret sql)",
    "sqlcmd -S srv -U sa -P $script:SaPassword",
    "sqlcmd -S srv -U sa -P $using:SqlPassword",
    "redis-cli -a $global:RedisAuth ping",
    "plink -pw ${env:PLINK_PW} alice@h",
    'sqlcmd -S srv -U sa -P "${SqlPassword}"',
    "ipmitool -P !IPMI_PASSWORD! -U admin",
    'ipmitool -U admin -P "!IpmiPassword!" chassis status',
]


@pytest.mark.parametrize("line", CLI_EXPANSIONS)
def test_shell_and_powershell_expansions_are_no_cli_password(line):
    assert "cli-password" not in _names(line), line
    found = ss.scan_text("ops/run.ps1", line + "\n", publish=True)
    assert "cli-password" not in _detectors(found)
    out, n = sp.redact(line)  # job output: scrubbed all the same
    assert n >= 1 and "[REDACTED:cli-password]" in out


@pytest.mark.parametrize("template", [
    'sqlcmd -S srv -U sa -P "({pw}"',       # quoted: "(" is literal text
    "sqlcmd -S srv -U sa -P '({pw})'",
    "ipmitool -P !{pw}! -U admin",          # !...! around a value that is no name
    "plink -pw {pw}$(x) alice@h",           # an expansion later in the value
])
def test_literals_that_merely_look_like_expansions_are_still_found(template):
    pw = "Xk9" + fakes.rand("v7-cli", 6) + "7q"
    line = template.replace("{pw}", pw)
    assert "cli-password" in _names(line), line


# --------------------------------------------------------------------------- #
# commit-msg: git's own scissors block and strip hint only
# --------------------------------------------------------------------------- #

_BLOCK = ("{c} ------------------------ >8 ------------------------\n"
          "{c} Do not modify or remove the line above.\n"
          "{c} Everything below it will be ignored.\n")
_HINT = ("{c} Please enter the commit message for your changes. Lines starting\n"
         "{c} with '{c}' will be ignored, and an empty message aborts the commit.\n")
_STATUS = "#\n# On branch main\n# Changes to be committed:\n#\tnew file:   scans/nmap_{lan}.xml\n#\n"
_DIFF = "diff --git a/a b/a\nindex 1..2 100644\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-gw {lan}\n+gw 192.0.2.10\n"


_SCISSORS_CLEANUP = ss.MessageConfig(cleanup="scissors")  # commit.cleanup=scissors (v8)


@pytest.mark.parametrize("raw,kept,config", [
    # git commit -v: hint, status, block, diff
    ("subject\n\n" + _HINT.format(c="#") + _STATUS + _BLOCK.format(c="#") + _DIFF, False, None),
    # cleanup=scissors: block, status (v8: only when git's configuration says scissors)
    ("subject\n\n" + _BLOCK.format(c="#") + _STATUS, False, _SCISSORS_CLEANUP),
    ("subject\n\n" + _BLOCK.format(c="#") + _STATUS, True, None),
    # cleanup=scissors and -v: block, status, block, diff
    ("subject\n\n" + _BLOCK.format(c="#") + _STATUS + _BLOCK.format(c="#") + _DIFF, False, None),
    # a pasted block with text after it: git keeps that text
    ("subject\n" + _BLOCK.format(c="#") + "host {lan}\n\n" + _HINT.format(c="#") + _STATUS, True, None),
    ("subject\n" + _BLOCK.format(c="#") + "#\nhost {lan}\n", True, None),
    ("subject\n" + _BLOCK.format(c="#") + "#\nhost {lan}\n", True, _SCISSORS_CLEANUP),
])
def test_a_scissors_block_counts_only_when_gits_text_follows_it(raw, kept, config):
    raw = raw.replace("{lan}", LAN)
    assert (LAN in ss.message_file_text(raw, editor=True, config=config or ss.MessageConfig())) is kept


@pytest.mark.parametrize("raw,kept", [
    # a hint line typed above git's template names another comment string
    ("subject\ndc with 'dc' will be ignored, and an empty message aborts the commit.\ndc {lan}\n\n"
     + _HINT.format(c="#") + _STATUS, True),
    # the same with git's lead line typed too: still not the LAST hint
    ("subject\n" + _HINT.format(c="dc") + "dc {lan}\n\n" + _HINT.format(c="#") + _STATUS, True),
    # a hint without git's lead line above it is not git's
    ("subject\n# {lan}\n# with '#' will be ignored, and an empty message aborts the commit.\n", True),
    # git's own template: its comment lines go
    ("subject\n\n" + _HINT.format(c="#") + "# {lan}\n" + _STATUS, False),
    ("subject\n\n" + _HINT.format(c=";") + "; {lan}\n", True),  # v8: ';' only when configured
])
def test_only_the_last_strip_hint_under_gits_lead_line_counts(raw, kept):
    raw = raw.replace("{lan}", LAN)
    assert (LAN in ss.message_file_text(raw, editor=True)) is kept


def test_a_strip_hint_on_the_configured_comment_string_counts():
    raw = "subject\n\n" + _HINT.format(c=";") + f"; {LAN}\n"  # core.commentChar=;
    assert LAN not in ss.message_file_text(raw, editor=True, config=ss.MessageConfig((";",)))


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


def _prepend_editor(tmp_path: Path, text: str) -> Path:
    body = tmp_path / "prepend.txt"
    body.write_text(text)
    script = tmp_path / "prepend.sh"
    script.write_text(f'#!/bin/sh\ncat "{body}" "$1" > "$1.new" && mv "$1.new" "$1"\n')
    script.chmod(0o755)
    return script


@pytest.mark.parametrize("spoof", [
    "subject\n" + _BLOCK.format(c="#") + "host {lan}\n",
    "subject\ndc with 'dc' will be ignored, and an empty message aborts the commit.\ndc {lan}\n",
])
def test_commit_msg_refuses_a_pasted_scissors_block_or_strip_hint(guarded, tmp_path, spoof):
    repo, _ = guarded
    repo.write("app/c.py", "z = 3\n")
    repo.git("add", "app/c.py")
    editor = _prepend_editor(tmp_path, spoof.replace("{lan}", LAN))
    proc = subprocess.run(["git", "commit", "-q"], cwd=repo.path,
                          env=dict(repo.env, GIT_EDITOR=str(editor), LC_ALL="C"),
                          capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "[ip-private]" in out and LAN not in out
    assert repo.git("log", "-1", "--format=%s").stdout.strip() == "guardrails"


# --------------------------------------------------------------------------- #
# pre-push: fetch the remote tips this clone lacks
# --------------------------------------------------------------------------- #

def _behind_clone(repo, remote, tmp_path) -> str:
    """main holds an old finding (pushed with --no-verify, as before the strict
    checks); a second clone then moves main; this clone does not fetch.
    Returns the remote's new main."""
    assert repo.commit("docs/old.md", f"old {LAN}\n", no_verify=True).returncode == 0
    assert repo.git("push", "-q", "--no-verify", "origin", "main", check=False).returncode == 0
    other = tmp_path / "other"
    subprocess.run(["git", "clone", "-q", str(remote.path), str(other)], env=repo.env, check=True,
                   capture_output=True)
    (other / "app").mkdir(exist_ok=True)
    (other / "app" / "b.py").write_text("b = 2\n")
    for args in (["add", "app/b.py"], ["commit", "-q", "-m", "b"], ["push", "-q", "--no-verify", "origin", "main"]):
        subprocess.run(["git", *args], cwd=other, env=repo.env, check=True, capture_output=True)
    new_main = remote.git("rev-parse", "refs/heads/main").stdout.strip()
    assert repo.git("cat-file", "-e", new_main, check=False).returncode != 0  # this clone lacks it
    repo.git("checkout", "-q", "-b", "feature")
    assert repo.commit("app/c.py", "c = 3\n").returncode == 0
    return new_main


def test_pre_push_fetches_the_tips_it_lacks_and_touches_no_ref(guarded, tmp_path):
    repo, remote = guarded
    new_main = _behind_clone(repo, remote, tmp_path)
    tracking = repo.git("rev-parse", "refs/remotes/origin/main").stdout.strip()
    refs_before = repo.git("for-each-ref", "--format=%(refname) %(objectname)").stdout
    proc = repo.git("push", "origin", "feature", check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert remote.git("rev-parse", "--verify", "-q", "refs/heads/feature", check=False).returncode == 0
    assert repo.git("cat-file", "-e", new_main, check=False).returncode == 0  # the objects came in
    # no ref moved or appeared but the one the push itself records; no FETCH_HEAD
    assert repo.git("rev-parse", "refs/remotes/origin/main").stdout.strip() == tracking
    refs_after = repo.git("for-each-ref", "--format=%(refname) %(objectname)").stdout
    assert set(refs_after.splitlines()) - set(refs_before.splitlines()) == {
        f"refs/remotes/origin/feature {repo.git('rev-parse', 'feature').stdout.strip()}"}
    assert not (repo.path / ".git" / "FETCH_HEAD").exists()


# Settings only `git fetch` reads (its index-pack checks objects against a
# skip list that does not exist): the hook's fetch fails while ls-remote, the
# scan and the push itself work. (git puts its own exec path first in a hook's
# PATH, so a shim named "git" would not be seen.)
_FETCH_FAILS = {"GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "fetch.fsckObjects", "GIT_CONFIG_VALUE_0": "true",
                "GIT_CONFIG_KEY_1": "fetch.fsck.skipList", "GIT_CONFIG_VALUE_1": "/nonexistent/skip-list"}


def test_pre_push_says_to_fetch_when_the_fetch_fails(guarded, tmp_path):
    repo, remote = guarded
    _behind_clone(repo, remote, tmp_path)
    proc = subprocess.run(["git", "push", "origin", "feature"], cwd=repo.path, env=dict(repo.env, **_FETCH_FAILS),
                          capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "docs/old.md:1: [ip-private]" in out and LAN not in out
    assert "behind the remote" in out and "Run 'git fetch origin', then push again" in out
    assert remote.git("rev-parse", "--verify", "-q", "refs/heads/feature", check=False).returncode != 0
    # after a fetch, the same push goes through
    repo.git("fetch", "-q", "origin")
    proc = repo.git("push", "-q", "origin", "feature", check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_pre_push_never_echoes_a_url_in_its_fetch_advice(guarded, tmp_path):
    repo, remote = guarded
    _behind_clone(repo, remote, tmp_path)
    hook = repo.path / ".githooks" / "pre-push"
    tip = repo.git("rev-parse", "feature").stdout.strip()
    url = str(remote.path)
    proc = subprocess.run(["bash", str(hook), url, url], input=f"refs/heads/feature {tip} refs/heads/feature "
                          f"{'0' * len(tip)}\n", cwd=repo.path, capture_output=True, text=True,
                          env=dict(repo.env, **_FETCH_FAILS))
    assert proc.returncode == 1 and "git fetch <remote>" in proc.stderr and url not in proc.stderr
