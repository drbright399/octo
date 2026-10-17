"""Guardrails v5 (review round of 2026-10-15): what the strict hooks still let
through or got wrong once the private repo had to meet the public standard.

* ``--range A..B --remote R`` skips commits R already has under any ref;
* ref and annotated-tag names get the publish-only checks;
* ``psa-ticket-id`` (publish-only) and ``cli-password`` (a secret);
* ``#`` lines of a commit message are checked unless git strips them;
* excerpts mask every value-like word on a reported line, what is glued to a
  hit, and never-public values in the path column;
* the report says how to resolve a publish-only refusal;
* ``--all-history`` scans a blob under its strictest name.

Every value is built at run time, so this file passes the scanner it tests."""
from __future__ import annotations

import base64
import importlib.util
import os
import re
import subprocess
import sys
import time

import pytest

from apps.octo.security import secret_patterns as sp
from apps.octo.tests.security import fakes
from apps.octo.tests.security.conftest import SCANNER

_SPEC = importlib.util.spec_from_file_location("scan_sensitive", SCANNER)
ss = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("scan_sensitive", ss)  # dataclasses resolve their module by name
_SPEC.loader.exec_module(ss)

LAN = fakes.ip(10, 20, 30, 40)
PW = "Q" + fakes.rand("v5-pw", 8) + "#7k"          # a short, real-looking password
TICKET = fakes.ticket(2026, 10, 15, 6)
MAIL = "ops" + "@" + "corp-mail.co"


def _fill(template: str) -> str:
    return template.replace("{pw}", PW).replace("{lan}", LAN)


def _names(text: str, *, publish: bool = False) -> set[str]:
    return {h.detector for h in sp.find_hits(text, publish=publish)}


def _detectors(findings) -> list[str]:
    return [f.detector for f in findings]


def _render(findings) -> str:
    return "\n".join(f.render() for f in findings)


# --------------------------------------------------------------------------- #
# cli-password
# --------------------------------------------------------------------------- #

CLI_POSITIVES = [
    "sshpass -p '{pw}' ssh admin@{lan}",
    "sshpass -v -p{pw} ssh admin@{lan}",
    "curl -u admin:{pw} http://{lan}/api",
    'curl -sSfu "admin:{pw}" https://host.example.com/',
    "curl --user=admin:{pw} https://host.example.com/",
    "curl https://host.example.com/x \\\n  -H 'Accept: text/plain' \\\n  -u admin:{pw}",
    "mysql -h {lan} -uroot -p{pw} app",
    "mariadb-dump -p'{pw}' app",
    "mysqldump --pass={pw} app",
    "net use \\\\{lan}\\c$ /user:admin {pw}",
    "NET USE Z: \\\\{lan}\\share {pw} /USER:corp\\admin",
    "smbclient //{lan}/share -U 'corp\\admin%{pw}'",
    "rpcclient -U admin%{pw} {lan}",
    "SSHPASS='{pw}' sshpass -e ssh admin@{lan}",
    "rdesktop -u admin -p {pw} {lan}",
    "xfreerdp /v:{lan} /u:admin /p:{pw}",
    "ldapsearch -x -H ldap://{lan} -D cn=admin -w {pw} -b dc=example,dc=com",
    "cmdkey /generic:{lan} /user:admin /pass:{pw}",
    "PsExec.exe \\\\{lan} -u admin -p {pw} cmd",
    "sudo docker exec db mysql -p'{pw}' -e 'select 1'",
]

CLI_NEGATIVES = [
    'sshpass -p "$SSHPASS" ssh admin@host',
    "sshpass -f ~/.ssh/pw ssh -p 2222 admin@host",
    'curl -u "$USER:$TOKEN" https://host.example.com/',
    "curl -u ${API_USER}:${API_PASS} https://host.example.com/",
    "curl -u admin https://host.example.com:8443/",
    "curl -u admin:admin https://host.example.com/",
    'mysql -u root -p -e "select 1"',
    'mysql -p"${DB_PASSWORD}" app',
    "net use \\\\host\\share /user:admin *",
    "net use \\\\host\\share /delete",
    "net use \\\\host\\share %PASSWORD% /user:admin",
    "smbclient //host/share -U 'admin%<password>'",
    "PGPASSWORD=changeme psql -h db",
    "xfreerdp /v:host /u:admin /p:****",
    "ldapsearch -x -w password -b dc=example,dc=com",
    # the option alone is everywhere: the program has to be on the same command line
    "mkdir -p {pw}",
    "grep -w {pw} notes.txt",
    "ssh -p 2222 admin@host",
    "docker run -p 8080:80 web",
    "echo mysql; mkdir -p{pw}",
    "gcc -pthread -o app main.c",
    "tool -p{pw}",
]


@pytest.mark.parametrize("template", CLI_POSITIVES)
def test_cli_password_finds_a_password_on_a_command_line(template):
    text = _fill(template)
    assert "cli-password" in _names(text), template
    out, n = sp.redact(text)
    assert n >= 1 and PW not in out
    rendered = _render(ss.scan_text("ops/run.sh", text + "\n", publish=True))
    assert PW not in rendered and LAN not in rendered


@pytest.mark.parametrize("template", CLI_NEGATIVES)
def test_cli_password_skips_placeholders_variables_and_other_programs(template):
    assert "cli-password" not in _names(_fill(template)), template


def test_cli_password_leaves_the_named_rules_their_findings():
    # A secret-named variable or flag is reported as before; cli-password
    # only adds the shapes nothing else named.
    assert "secret-assignment" in _names(f"PGPASSWORD={PW} psql -h db")
    assert "cli-secret-flag" in _names(f"mysqldump --password={PW} app")


@pytest.mark.parametrize("text", [
    "mkdir -p x " * 60_000,
    "-p " * 100_000,
    "curl -u a:b " * 20_000,
    "\\\\h\\s x " * 50_000,
    "ldapsearch \\\n" * 30_000 + "-w " + PW,
    "net use " + "/user:a b " * 40_000,
])
def test_cli_password_stays_linear_on_hostile_input(text):
    start = time.monotonic()
    sp.find_hits(text, publish=True)
    sp.redact(text)
    assert time.monotonic() - start < 3.0


# --------------------------------------------------------------------------- #
# psa-ticket-id
# --------------------------------------------------------------------------- #

def test_psa_ticket_numbers_are_never_public_but_the_fixture_is_fine():
    for text in (f"see {TICKET}", f"fix/{TICKET.lower()}-printer", f"x_{TICKET}", f"({TICKET})"):
        assert "psa-ticket-id" in _names(text, publish=True), text
        assert "psa-ticket-id" not in _names(text)  # publish-only
    for text in ("fixture T20000101.0001", "fixture t20000101.0001",
                 fakes.ticket(2026, 13, 1, 1), fakes.ticket(2026, 10, 15, 6, prefix="AT"),
                 TICKET + "1", TICKET[1:], "v1.2.3.4"):
        assert "psa-ticket-id" not in _names(text, publish=True), text


def test_psa_ticket_numbers_in_contents_messages_and_ref_names_are_masked():
    found = ss.scan_text("docs/notes.md", f"printer fixed ({TICKET})\n", publish=True)
    assert _detectors(found) == ["psa-ticket-id"] and TICKET not in _render(found)
    found = ss.scan_message(ss.COMMIT_MESSAGE, f"fix: printer\n\nCloses {TICKET}\n", publish=True, local=None)
    assert _detectors(found) == ["psa-ticket-id"] and TICKET not in _render(found)
    found = ss.scan_ref_name(f"refs/heads/fix/{TICKET}", local=None, publish=True)
    assert _detectors(found) == ["ref:psa-ticket-id"] and TICKET not in _render(found)


# --------------------------------------------------------------------------- #
# Ref names get the publish-only checks
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,detector,value", [
    (f"refs/heads/fix/{LAN}-gw", "ref:ip-private", LAN),
    (f"refs/heads/feat/{MAIL}", "ref:email-address", MAIL),
    (f"refs/heads/fix/{TICKET}", "ref:psa-ticket-id", TICKET),
    ("refs/heads/host.tail1234." + "ts.net", "ref:tailnet-name", "tail1234"),
    (f"refs/tags/v1-{LAN}", "ref:ip-private", LAN),
])
def test_ref_names_get_the_publish_checks(name, detector, value):
    found = ss.scan_ref_name(name, local=None, publish=True)
    assert detector in _detectors(found) and value not in _render(found)
    assert ss.scan_ref_name(name, local=None) == []  # without --publish, as before
    found = ss.scan_tag_name(name.rpartition("/")[2], local=None, publish=True)
    assert detector in _detectors(found) and value not in _render(found)


@pytest.mark.parametrize("name", [
    "refs/heads/main", "refs/tags/v1.2.3.4", "refs/tags/v0.17.6", "refs/heads/fix/192.0.2.10-gw",
    "refs/heads/fix/T20000101.0001-fixture", "refs/heads/release/2026-10-15",
])
def test_ordinary_ref_names_pass_the_publish_checks(name):
    assert ss.scan_ref_name(name, local=None, publish=True) == []


def test_the_ref_name_cli_runs_the_publish_checks(tmp_path):
    run = [sys.executable, str(SCANNER), "--no-local-block", "--ref-name", f"refs/heads/fix/{LAN}"]
    assert subprocess.run(run, capture_output=True).returncode == 0
    proc = subprocess.run(run + ["--publish"], capture_output=True, text=True)
    assert proc.returncode == 1 and "<ref-name>:0: [ref:ip-private]" in proc.stdout and LAN not in proc.stdout


# --------------------------------------------------------------------------- #
# Commit messages: '#' lines and the scissors line
# --------------------------------------------------------------------------- #

_STRIP_HINT = ("# Please enter the commit message for your changes. Lines starting\n"
               "# with '#' will be ignored, and an empty message aborts the commit.\n")
_KEEP_HINT = ("# Please enter the commit message for your changes. Lines starting\n"
              "# with '#' will be kept; you may remove them yourself if you want to.\n"
              "# An empty message aborts the commit.\n")
_SCISSORS = ("# ------------------------ >8 ------------------------\n"
             "# Do not modify or remove the line above.\n# Everything below it will be ignored.\n")


def _message(tmp_path, text: str, editor: str, **git_config: str) -> subprocess.CompletedProcess:
    """The scanner on a message file; ``git_config``: settings git passes on
    to the hook (``git -c core.commentChar=;``), as GIT_CONFIG_* variables."""
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text(text)
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") and k != ss.LOCAL_BLOCK_ENV}
    if editor:
        env["GIT_EDITOR"] = editor
    for i, (key, value) in enumerate(git_config.items()):
        env.update({f"GIT_CONFIG_KEY_{i}": key.replace("__", "."), f"GIT_CONFIG_VALUE_{i}": value})
    if git_config:
        env["GIT_CONFIG_COUNT"] = str(len(git_config))
    return subprocess.run([sys.executable, str(SCANNER), "--no-local-block", "--message", str(msg), "--publish"],
                          capture_output=True, text=True, env=env)


def test_hash_lines_git_keeps_are_checked(tmp_path):
    body = f"feat: d\n\n# Notes\n# gw {LAN} and /ho" + "me/bob/x\n"
    proc = _message(tmp_path, body, ":")  # git commit -m: git runs the hook with GIT_EDITOR=:
    assert proc.returncode == 1 and LAN not in proc.stdout
    assert "<commit-message>:4: [ip-private]" in proc.stdout and "<commit-message>:4: [home-path]" in proc.stdout
    # an editor with cleanup=whitespace: git says it keeps them, so they are checked
    proc = _message(tmp_path, "feat: d\n\n" + _KEEP_HINT + f"# gw {LAN}\n", "vi")
    assert proc.returncode == 1 and "[ip-private]" in proc.stdout


def test_the_template_git_strips_is_not_checked(tmp_path):
    # An editor ran and git's own hint says '#' lines go: the untracked file
    # names and the author line of the template never reach the commit.
    template = ("feat: d\n\n" + _STRIP_HINT + "#\n# Author:    Bob <" + MAIL + ">\n#\n"
                "# Untracked files:\n#\tgw-" + LAN + ".txt\n")
    assert _message(tmp_path, template, "vi").returncode == 0
    assert _message(tmp_path, template, "").returncode == 0  # no GIT_EDITOR: git's default editor ran
    # the same text without an editor: git keeps every line (the hint is just text)
    assert _message(tmp_path, template, ":").returncode == 1
    # a comment string other than '#' (git's configuration, v8): only those lines go
    semi = (f"feat: d\n\n; Please enter the commit message for your changes. Lines starting\n"
            f"; with ';' will be ignored, and an empty message aborts the commit.\n; gw {LAN}\n# gw {LAN}\n")
    proc = _message(tmp_path, semi, "vi", core__commentChar=";")
    assert proc.returncode == 1 and "<commit-message>:6: [ip-private]" in proc.stdout
    assert "<commit-message>:5:" not in proc.stdout
    # the same text with git's default '#': the ';' hint is just text, both lines are checked
    proc = _message(tmp_path, semi, "vi")
    assert "<commit-message>:5: [ip-private]" in proc.stdout and "<commit-message>:6: [ip-private]" in proc.stdout


def test_the_scissors_line_counts_only_when_git_wrote_it(tmp_path):
    verbose = "feat: d\n\n" + _STRIP_HINT + _SCISSORS + f"diff --git a/x b/x\n+gw {LAN}\n"
    assert _message(tmp_path, verbose, "vi").returncode == 0      # git commit -v: the diff is cut
    assert _message(tmp_path, verbose, ":").returncode == 1       # typed into -m: git keeps it all


# --------------------------------------------------------------------------- #
# --range A..B --remote R: commits R already holds under any ref
# --------------------------------------------------------------------------- #

def test_range_skips_commits_the_remote_has_under_any_ref(make_repo):
    remote = make_repo("remote.git", bare=True)
    repo = make_repo()
    repo.git("remote", "add", "origin", str(remote.path))
    repo.commit("a.py", "x = 1\n")
    repo.git("push", "-q", "origin", "main")
    base = repo.git("rev-parse", "HEAD").stdout.strip()
    repo.git("checkout", "-q", "-b", "feature")
    repo.commit("docs/net.md", f"gateway {LAN}\n")    # pushed before the strict checks
    repo.commit("docs/net.md", "gateway 192.0.2.10\n")
    repo.git("push", "-q", "origin", "feature")
    tip = repo.git("rev-parse", "HEAD").stdout.strip()
    spec = f"{base}..{tip}"
    strict = ("--no-local-block", "--publish")
    assert repo.scan("--range", spec, *strict).returncode == 1                     # exactly that range
    assert repo.scan("--range", spec, "--remote", "origin", *strict).returncode == 0  # all on origin
    proc = repo.scan("--range", spec, "--remote", str(remote.path), *strict)       # a URL: none known
    assert proc.returncode == 1 and "docs/net.md:1: [ip-private]" in proc.stdout
    repo.commit("docs/new.md", f"gw {LAN}\n")                                      # brand new
    proc = repo.scan("--range", f"{base}..HEAD", "--remote", "origin", *strict)
    assert proc.returncode == 1 and "docs/new.md:1: [ip-private]" in proc.stdout
    assert "docs/net.md" not in proc.stdout


# --------------------------------------------------------------------------- #
# Excerpts: what else is on a reported line stays masked
# --------------------------------------------------------------------------- #

REPROS = [  # the reviewer's repros: a short password on a line whose IP is reported
    ("sshpass -p '{pw}' ssh admin@{lan}", "sshpass"),
    ("curl -u admin:{pw} http://{lan}/api", "curl"),
    ("mysql -h {lan} -uroot -p{pw} app", "mysql"),
    ("net use \\\\{lan}\\c$ /user:admin {pw}", "net use"),
]


@pytest.mark.parametrize("cli_detector", [True, False], ids=["detected", "masking-only"])
@pytest.mark.parametrize("template,word", REPROS)
def test_a_short_password_next_to_an_ip_is_masked(template, word, cli_detector, monkeypatch):
    if not cli_detector:  # the excerpt alone must hide it, whatever the detectors know
        monkeypatch.setattr(sp, "DETECTORS", tuple(d for d in sp.DETECTORS if "cli-password" not in d.reported))
    found = ss.scan_text("ops/deploy.sh", _fill(template) + "\n", publish=True)
    rendered = _render(found)
    assert "ip-private" in _detectors(found)
    assert LAN not in rendered
    assert not any(PW[i:i + 6] in rendered for i in range(len(PW) - 5)), rendered.replace(PW, "<pw>")
    # still enough to find the problem: the detector, the column, the command
    assert re.search(r"ops/deploy\.sh:1: \[ip-private\] col \d+: ", rendered)
    assert word in rendered


def test_value_like_words_of_eight_or_more_are_masked_and_names_stay_readable():
    token = "Zq" + fakes.rand("v5-word", 6, fakes.HEX) + "x9"  # 10 characters, letters and digits
    line = (f"deploy {token} from src/app.py to {LAN} "
            f"as svc_backup on rmm.vendor.invalid, release v0.17.6, 2026-10-15\n")
    rendered = _render(ss.scan_text("ops/notes.md", line, publish=True))
    assert token not in rendered and LAN not in rendered
    for readable in ("deploy", "src/app.py", "svc_backup", "rmm.vendor.invalid",
                     "v0.17.6", "2026-10-15"):
        assert readable in rendered, readable
    # symbols a password carries count without digits too
    symbolic = "Kq!xWm#zRt"
    rendered = _render(ss.scan_text("ops/notes.md", f"pw {symbolic} on {LAN}\n", publish=True))
    assert symbolic not in rendered


def test_the_rest_of_a_composite_value_next_to_a_hit_is_masked():
    key = base64.b64encode(fakes.key_bytes("v5-composite")).decode()
    short = fakes.rand("v5-short", 5)
    rendered = _render(ss.scan_text("ops/wg.txt", f"WG_PAIR={key}:{short}\n"))
    assert "fernet-or-base64-key" in rendered and key not in rendered and short not in rendered
    assert "WG_PAIR=" in rendered
    # a port after an IP and a user name before one stay readable
    rendered = _render(ss.scan_text("ops/x.sh", f"ssh admin@{LAN}:2222 && curl http://{LAN}:8443/\n",
                                    publish=True))
    assert LAN not in rendered and "admin@" in rendered and ":2222" in rendered and ":8443/" in rendered
    # user%<hit>: the user stays, a value glued after the hit goes
    rendered = _render(ss.scan_text("ops/x.sh", f"{key}%{short}/x\n"))
    assert short not in rendered


def test_never_public_values_in_the_path_column_are_masked():
    leak = f"client_secret = '{fakes.rand('v5-path', 32)}'\n".encode()
    for path, value in ((f"notes/gw-{LAN}.txt", LAN), (f"notes/{MAIL}.md", MAIL),
                        (f"tickets/{TICKET}.md", TICKET)):
        for publish in (True, False):
            found = ss.scan_blob(path, leak, publish=publish, local=None)
            assert "secret-assignment" in _detectors(found)
            assert value not in _render(found), (path.replace(value, "<v>"), publish)
    found = ss.path_findings(f"notes/gw-{LAN}.txt", b"", None, publish=True)
    assert _detectors(found) == ["path:ip-private"] and LAN not in _render(found)


# --------------------------------------------------------------------------- #
# The report says how to resolve a refusal
# --------------------------------------------------------------------------- #

def _advice(*findings: ss.Finding) -> str:
    return ss._advice({f.detector for f in findings})


def test_the_report_explains_publish_only_refusals():
    text = _advice(ss.Finding("docs/net.md", 1, "ip-private", "x"))
    assert "allow[ip-private]" in text and "secret detectors only" in text
    assert "192.0.2.0/24" in text and "T20000101.0001" in text
    assert "treat it as exposed" not in text
    text = _advice(ss.Finding("x", 0, "path:email-address", "x"), ss.Finding("x", 0, "ref:psa-ticket-id", "x"))
    assert "allow[email-address]" in text and "psa-ticket-id" in text and "rename it" in text
    text = _advice(ss.Finding("app/x.py", 1, "secret-assignment", "x"))
    assert "treat it as exposed" in text and "allow[" not in text
    text = _advice(ss.Finding("x", 1, "local-block", "x"))
    assert "cannot be allowed inline" in text and "allow[" not in text


def test_binary_file_wording_fits_a_commit_in_the_private_repo():
    found = ss.scan_blob("tools/agent.bin", b"\x7fELF\x02\x01\x01\x00" + bytes(range(256)),
                         publish=True, local=None)
    binary = [f for f in found if f.detector == "binary-file"]
    assert binary and "allowlist" not in binary[0].excerpt
    assert "outside the repository" in binary[0].excerpt
    assert "outside the repository" in _advice(*binary)


# --------------------------------------------------------------------------- #
# --all-history: a blob under several names gets the strictest rules
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("weak,strict,content,detector,publish", [
    # a generated name skips the 32-byte-key and entropy rules
    ("dist/app.min.js", "src/settings.py",
     "k " + base64.b64encode(fakes.key_bytes("v5-hist-key")).decode() + "\n", "fernet-or-base64-key", False),
    # a lockfile skips e-mail addresses
    ("a/package-lock.json", "b/contacts.md", '"author": "jane.doe' + "@" + 'corp-mail.co"\n',
     "email-address", True),
    # a binary extension gets the strings of the content only
    ("a/logo.png", "b/notes.txt", "client_secret = '" + fakes.rand("v5-hist-bin", 32) + "'\n",
     "secret-assignment", False),
])
def test_all_history_scans_a_blob_under_its_strictest_name(make_repo, weak, strict, content, detector,
                                                            publish):
    repo = make_repo()
    repo.commit(weak, content)   # tree order puts the weak name first
    repo.commit(strict, content)  # the same blob under a second name
    args = ["--all-history", "--no-local-block"] + (["--publish"] if publish else [])
    proc = repo.scan(*args)
    assert proc.returncode == 1 and f"{strict}:1: [{detector}]" in proc.stdout, proc.stdout
    assert content.split()[-1].strip("'\"") not in proc.stdout


def test_a_line_with_thousands_of_hits_and_words_is_masked_quickly():
    # Each word is matched against the hits it overlaps (a sorted index), not
    # against every hit of the line: a minified bundle stays linear.
    line = " ".join(f"{fakes.ip(10, i % 250, (i // 250) % 250, i % 7 + 1)} word{i}x" for i in range(20_000))
    start = time.monotonic()
    found = ss.scan_text("web/dist/app.js", line + "\n", publish=True)
    assert "ip-private" in _detectors(found) and time.monotonic() - start < 5.0
    long_hit = "k " + base64.b64encode(fakes.key_bytes("v5-long")).decode() + " " + " ".join(
        f"{fakes.ip(10, 1, i % 250, 1)}" for i in range(20_000))
    start = time.monotonic()
    ss.scan_text("web/dist/app.js", long_hit + "\n", publish=True)
    assert time.monotonic() - start < 5.0


def test_the_span_index_finds_exactly_the_overlapping_hits():
    spans = [(0, 4), (2, 6), (10, 12), (20, 40), (25, 30)]
    index = ss._Spans(spans)
    assert index.spans == [(0, 6), (10, 12), (20, 40)]
    assert index.overlapping(5, 11) == [(0, 6), (10, 12)]
    assert index.overlapping(6, 10) == [] and index.overlapping(12, 20) == []
    assert index.overlapping(30, 31) == [(20, 40)] and ss._Spans([]).overlapping(0, 9) == []
