"""Guardrails v6 (review round 3 of 2026-10-15): what the v5 hooks still got
wrong.

* parallel ``scripts/install_hooks.sh`` runs are serialized by a lock and
  never leave core.hooksPath naming a missing directory;
* ``cli-password`` is one detector per option shape, so a candidate one
  family rejects never hides another family's finding; new MSP forms
  (ConvertTo-SecureString, plink -pw, sqlcmd -P, ...), redacted in Datto job
  output too;
* in a word that holds a hit, the rest is cut at field separators only and
  judged Unicode-aware: a password glued to an IP never prints in clear;
* an IP joined by ``_`` is found (contents, file names, ref and tag names);
* pre-push asks the remote what it holds (``ls-remote``), never a stale
  remote-tracking ref;
* ref names: detectors that are not judged are left out before overlaps;
* commit-msg honours only git's own scissors block.

Every value is built at run time, so this file passes the scanner it tests."""
from __future__ import annotations

import importlib.util
import os
import random
import string
import subprocess
import sys
import time
from pathlib import Path

import pytest

from apps.octo.security import secret_patterns as sp
from apps.octo.tests.security import fakes
from apps.octo.tests.security.conftest import SCANNER

_SPEC = importlib.util.spec_from_file_location("scan_sensitive", SCANNER)
ss = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("scan_sensitive", ss)  # dataclasses resolve their module by name
_SPEC.loader.exec_module(ss)

LAN = fakes.ip(10, 20, 30, 40)
PW = "Zq7" + fakes.rand("v6-pw", 7) + "#2w"          # a short, real-looking password
PW_COLON = "Zq7" + fakes.rand("v6-pwc", 3) + ":" + fakes.rand("v6-pwc2", 6)
TICKET = fakes.ticket(2026, 10, 15, 42)
MAIL = "bob" + "@" + "corpmail.com"
SECRET = fakes.rand("v6-hook-secret", 32)
LEAK = f"client_secret = '{SECRET}'\n"
HOOKS = ("pre-commit", "commit-msg", "pre-push")


def _fill(template: str) -> str:
    return template.replace("{pw}", PW).replace("{pwc}", PW_COLON).replace("{lan}", LAN)


def _names(text: str, *, publish: bool = False) -> set[str]:
    return {h.detector for h in sp.find_hits(text, publish=publish)}


def _detectors(findings) -> list[str]:
    return [f.detector for f in findings]


def _render(findings) -> str:
    return "\n".join(f.render() for f in findings)


def _no_piece(secret: str, text: str, n: int = 6) -> bool:
    return not any(secret[i:i + n] in text for i in range(len(secret) - n + 1))


# --------------------------------------------------------------------------- #
# install_hooks.sh: concurrent runs, the lock, the final check
# --------------------------------------------------------------------------- #

def _install(repo, *args: str, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(repo.path / "scripts" / "install_hooks.sh"), *args],
                          cwd=repo.path, env=env or repo.env, capture_output=True, text=True)


def _assert_hooks_live(repo) -> Path:
    git_dir = repo.path / ".git"
    pinned = git_dir / "athena-guardrails"
    assert pinned.is_symlink()
    live = git_dir / os.readlink(pinned)
    assert live.is_dir(), f"the link names a missing directory: {live.name}"
    hooks_path = Path(repo.git("config", "core.hooksPath").stdout.strip())
    assert hooks_path == pinned / "hooks"
    for hook in HOOKS:
        assert (hooks_path / hook).stat().st_mode & 0o111, hook
    assert (hooks_path / "lib-scan.sh").is_file()
    assert (pinned / "scripts" / "scan_sensitive.py").is_file()
    return live


def test_concurrent_installs_always_leave_a_working_hooks_directory(make_repo):
    repo = make_repo()
    repo.install_guardrails()
    assert _install(repo).returncode == 0
    script = str(repo.path / "scripts" / "install_hooks.sh")
    git_dir = repo.path / ".git"
    for _ in range(4):
        procs = [subprocess.Popen(["bash", script], cwd=repo.path, env=repo.env, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(4)]
        results = [(p.wait(timeout=120), p.communicate()) for p in procs]
        assert all(rc == 0 for rc, _ in results), [err for _, (_, err) in results]
        _assert_hooks_live(repo)
        leftovers = sorted(p.name for p in git_dir.iterdir()
                           if p.name.startswith("athena-guardrails.") and ".v" not in p.name)
        assert leftovers == []  # no lock, no spare link, nothing retired
        assert len([p for p in git_dir.iterdir() if p.name.startswith("athena-guardrails.v")]) <= 2
    proc = repo.commit("app/settings.py", LEAK)  # the hooks still run and still block
    assert proc.returncode != 0 and "[secret-assignment]" in proc.stdout + proc.stderr


def _host() -> str:
    """The host name install_hooks.sh records in its lock."""
    return subprocess.run(["bash", "-c", "hostname 2>/dev/null || uname -n"], capture_output=True,
                          text=True).stdout.strip()


def test_a_stale_install_lock_is_broken(make_repo):
    repo = make_repo()
    repo.install_guardrails()
    lock = repo.path / ".git" / "athena-guardrails.lock"
    gone = subprocess.Popen(["true"])
    gone.wait()  # a process id that no longer runs
    lock.mkdir()
    (lock / "owner").write_text(f"{gone.pid} {int(time.time())} {_host()}\n")
    proc = _install(repo)
    assert proc.returncode == 0, proc.stderr
    assert "stale lock" in proc.stderr and not lock.exists()
    _assert_hooks_live(repo)
    # the same process id recorded on another host (a container, a shared
    # disk) says nothing here: that lock is waited for, not broken
    lock.mkdir()
    (lock / "owner").write_text(f"{gone.pid} {int(time.time())} elsewhere.invalid\n")
    proc = _install(repo, env=dict(repo.env, ATHENA_GUARDRAILS_LOCK_WAIT="1"))
    assert proc.returncode == 1 and "another install holds" in proc.stderr and lock.is_dir()
    (lock / "owner").unlink()
    lock.rmdir()
    # a lock left without an owner line (killed between mkdir and write): stale by age
    lock.mkdir()
    old = time.time() - 120
    os.utime(lock, (old, old))
    proc = _install(repo, env=dict(repo.env, ATHENA_GUARDRAILS_LOCK_STALE="60"))
    assert proc.returncode == 0, proc.stderr
    assert not lock.exists()


def test_a_held_install_lock_is_waited_for_and_never_taken(make_repo):
    repo = make_repo()
    repo.install_guardrails()
    assert _install(repo).returncode == 0
    pinned = repo.path / ".git" / "athena-guardrails"
    before = os.readlink(pinned)
    lock = repo.path / ".git" / "athena-guardrails.lock"
    lock.mkdir()
    (lock / "owner").write_text(f"{os.getpid()} {int(time.time())} {_host()}\n")  # alive: this test
    try:
        proc = _install(repo, env=dict(repo.env, ATHENA_GUARDRAILS_LOCK_WAIT="1"))
        assert proc.returncode == 1 and "another install holds" in proc.stderr
        assert os.readlink(pinned) == before and lock.is_dir()
        assert not [p for p in pinned.parent.iterdir() if p.name.startswith("athena-guardrails.v")
                    and p.name != before]
    finally:
        (lock / "owner").unlink()
        lock.rmdir()
    assert _install(repo).returncode == 0


def test_install_fails_loudly_when_git_would_not_find_the_hooks(make_repo, tmp_path):
    # An environment override of core.hooksPath wins over the clone's config:
    # git would run no hooks at all. The installer must say so and fail.
    repo = make_repo()
    repo.install_guardrails()
    env = dict(repo.env, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.hooksPath",
               GIT_CONFIG_VALUE_0=str(tmp_path / "nowhere"))
    proc = _install(repo, env=env)
    assert proc.returncode == 1 and "NOT active" in proc.stderr
    assert _install(repo).returncode == 0
    _assert_hooks_live(repo)


# --------------------------------------------------------------------------- #
# cli-password: one detector per option shape
# --------------------------------------------------------------------------- #

SHADOW_REPROS = [
    # the glued "-p<pw>" shape (mysql) matched "-p:<pw>" first and was rejected
    "xfreerdp /v:srv /u:alice -p:{pw}",
    "winrs -r:srv -u:alice -p:{pw} ipconfig",
    # the curl "-U user:<pw>" shape matched "-U user%<pw-with-colon>" first
    "smbclient //srv/share -U alice%{pwc}",
    "rpcclient -U 'alice%{pwc}' srv",
    # after other commands on the line whose options look alike
    "curl -sS https://host.example.com/ && smbclient //srv/share -U alice%{pwc}",
    "mysql -e 'select 1' ; xfreerdp /v:srv -p:{pw}",
    "curl -u a:b https://host.example.com/ ; xfreerdp /v:srv -p:{pw}",
    # "-pw <pw>" is no glued "-p<pw>" for mysql, and "-P" no "-p"
    "plink -ssh -pw {pw} alice@srv",
    "sqlcmd -S srv -U sa -P {pw}",
]


@pytest.mark.parametrize("template", SHADOW_REPROS)
def test_a_rejected_option_shape_never_hides_another(template):
    text = _fill(template)
    secret = PW_COLON if "{pwc}" in template else PW
    assert "cli-password" in _names(text), template
    out, n = sp.redact(text)
    assert n >= 1 and _no_piece(secret, out), out.replace(secret, "<pw>")
    rendered = _render(ss.scan_text("ops/run.sh", text + "\n", publish=True))
    assert "[cli-password]" in rendered and _no_piece(secret, rendered)


def test_every_family_is_a_detector_of_its_own_reporting_cli_password():
    families = [d for d in sp.DETECTORS if "cli-password" in d.reported]
    assert len(families) >= 15 and all(d.reported == ("cli-password",) for d in families)
    assert len({d.name for d in families}) == len(families)
    assert all(d.needles for d in families)  # each is skipped on text without its program


CLI_POSITIVES_V6 = [
    "$cred = ConvertTo-SecureString '{pw}' -AsPlainText -Force",
    'ConvertTo-SecureString -String "{pw}" -AsPlainText -Force',
    "ConvertTo-SecureString -AsPlainText -Force {pw}",
    "convertto-securestring '{pw}' -asplain -f",
    "$p = ConvertTo-SecureString '{pw}' `\n    -AsPlainText -Force",
    "New-Object PSCredential('admin', (ConvertTo-SecureString \"{pw}\" -AsPlainText -Force))",
    "plink -ssh -pw {pw} admin@{lan}",
    "PSCP.EXE -pw '{pw}' backup.tgz admin@{lan}:/srv",
    "psftp -pw {pw} admin@{lan}",
    'sqlcmd -S {lan} -U sa -P {pw} -Q "select 1"',
    "bcp app.dbo.t out t.dat -S {lan} -U sa -P{pw}",
    "ipmitool -I lanplus -H {lan} -U admin -P {pw} chassis status",
    "winrs -r:{lan} -u:admin -p:{pw} ipconfig",
    "docker login -u admin -p {pw} registry.example.com",
    "7z a -p{pw} -mhe=on backup.7z data",
    "zip -r -P {pw} backup.zip data",
    "unzip -P '{pw}' backup.zip",
    "redis-cli -h {lan} -a {pw} ping",
    "REDISCLI_AUTH={pw} redis-cli -h {lan} ping",
]

CLI_NEGATIVES_V6 = [
    "$cred = ConvertTo-SecureString $pw -AsPlainText -Force",
    "ConvertTo-SecureString '<password>' -AsPlainText -Force",
    'ConvertTo-SecureString "$env:SVC_PW" -AsPlainText -Force',
    "ConvertTo-SecureString (Get-Content pw.txt) -AsPlainText -Force",
    "ConvertTo-SecureString '{pw}'",  # no -AsPlainText: an encrypted standard string
    "plink -pw %PLINK_PW% admin@host",
    "sqlcmd -S db -U sa -P $(SqlPassword)",
    'sqlcmd -S db -E -Q "select 1"',
    "ipmitool -I lanplus -H host -U admin -E chassis status",
    "ipmitool -P **** chassis status",
    "docker login -u admin --password-stdin registry.example.com",
    "docker run -p 8080:80 -p {pw} web",
    "7z a -p backup.7z data",
    "zip -P <password> backup.zip data",
    "redis-cli -a $REDIS_PASSWORD ping",
    "winrs -r:host -p:%WINRS_PW% ipconfig",
    "gzip -P {pw} notes.txt",
    "tar -P {pw}",
    "mkdir -p {pw}",
]


@pytest.mark.parametrize("template", CLI_POSITIVES_V6)
def test_msp_command_line_password_forms_are_found_and_redacted(template):
    from apps.octo.adapters.datto.job_output import normalize_job_output

    text = _fill(template)
    assert "cli-password" in _names(text), template
    out, n = sp.redact(text)
    assert n >= 1 and PW not in out and "[REDACTED:" in out
    record = normalize_job_output({"stdout": text, "stderr": "", "exit": 0})  # Datto job output
    assert PW not in record.stdout and record.redactions >= 1
    rendered = _render(ss.scan_text("ops/run.ps1", text + "\n", publish=True))
    assert "[cli-password]" in rendered and _no_piece(PW, rendered) and LAN not in rendered


@pytest.mark.parametrize("template", CLI_NEGATIVES_V6)
def test_msp_command_line_placeholders_and_other_programs_stay_quiet(template):
    assert "cli-password" not in _names(_fill(template)), template


@pytest.mark.parametrize("text", [
    "ConvertTo-SecureString " * 40_000,
    "ConvertTo-SecureString -a -f " * 30_000,
    "ConvertTo-SecureString 'x' `\n" * 30_000,
    "plink " + "-pw x " * 60_000,
    "sqlcmd " + "-P x " * 60_000,
    "docker " + "--x " * 60_000 + "login -p " + PW,
    "redis-cli " + "-a x " * 60_000,
    "winrs " + "-p:x " * 60_000,
])
def test_new_families_stay_linear_on_hostile_input(text):
    start = time.monotonic()
    sp.find_hits(text, publish=True)
    sp.redact(text)
    assert time.monotonic() - start < 4.0


# --------------------------------------------------------------------------- #
# Excerpts: a password glued to a hit
# --------------------------------------------------------------------------- #

def _glued_repros() -> list[tuple[str, str]]:
    brackets = "Xk9(" + fakes.rand("v6-m1", 3) + "2)pL7v"
    squares = "Wq3[" + fakes.rand("v6-m2", 3) + "8]Hn5{" + fakes.rand("v6-m3", 3) + "6}"
    umlauts = "Grün7wäld9xéK2"
    return [
        (f"{LAN},admin,{brackets}", brackets),
        (f"{LAN};admin;{squares}", squares),
        (f"admin:{umlauts}@{LAN}", umlauts),
        (f"see {LAN},{umlauts}", umlauts),
        (f"{LAN} {umlauts}", umlauts),
        (f"{LAN}#{brackets}", brackets),
        (f"<{LAN}>{squares}", squares),
    ]


@pytest.mark.parametrize("line,secret", _glued_repros())
def test_a_password_glued_to_a_hit_is_masked(line, secret):
    found = ss.scan_text("notes.csv", line + "\n", publish=True)
    rendered = _render(found)
    assert "ip-private" in _detectors(found) and LAN not in rendered
    assert _no_piece(secret, rendered), rendered.replace(secret, "<pw>")


@pytest.mark.parametrize("line,readable", [
    ("{lan},admin,backup2", ",admin,backup2"),
    ("ssh admin@{lan}:2222", "ssh admin@"),
    ("ssh admin@{lan}:2222", ":2222"),
    ("curl http://{lan}:8443/api/v1/devices", ":8443/api/v1/devices"),
    ("dir \\\\{lan}\\share", "\\share"),
    ("{lan},rmm.vendor.invalid,admin", ",rmm.vendor.invalid,admin"),
])
def test_names_ports_and_hosts_glued_to_a_hit_stay_readable(line, readable):
    rendered = _render(ss.scan_text("ops/notes.md", _fill(line) + "\n", publish=True))
    assert LAN not in rendered and readable in rendered, rendered


_FUZZ_ALPHABET = (string.ascii_letters + string.digits + "!#$%^&*()[]{}<>?~|+-_."
                  + "äöüßéèñøåçÄÖÜÉÑØ")
_GLUE = ["{ip},admin,{pw}", "{ip};admin;{pw}", "admin:{pw}@{ip}", "see {ip},{pw}", "{ip}/{pw}",
         "{ip}#{pw}", "<{ip}>{pw}", "{pw}@{ip}", "{ip}={pw}", "\\\\{ip}\\{pw}", "{ip}:{pw}",
         "{pw},{ip}", "{pw};{ip}", "{ip}%{pw}", "x={ip};y={pw}"]


def test_fuzz_no_six_character_piece_of_a_glued_password_is_printed():
    # Passwords of 8 to 24 characters from letters, digits, the punctuation a
    # generator uses and non-ASCII letters, glued to a reported IP by every
    # common separator. A password that itself contains a field separator
    # (, ; / \ @ = :) cannot be told apart from two fields and is not drawn.
    # (A separate word is judged by _word_value: letters alone read as a word.)
    rng = random.Random("secret-guardrails:v6-fuzz")
    for _ in range(600):
        pw = "".join(rng.choice(_FUZZ_ALPHABET) for _ in range(rng.randint(8, 24)))
        template = rng.choice(_GLUE)
        line = template.replace("{ip}", LAN).replace("{pw}", pw)
        found = ss.scan_text("ops/hosts.csv", line + "\n", publish=True)
        rendered = _render(found)
        assert "ip-private" in _detectors(found), template
        assert _no_piece(pw, rendered), (template, rendered.replace(pw, "<pw>"))


# --------------------------------------------------------------------------- #
# IPs joined by '_'
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("text", ["host_{lan}", "{lan}_dc", "dc_{lan}", "scan nmap_{lan}.xml", "__{lan}__"])
def test_an_ip_joined_by_underscore_is_found_in_contents(text):
    text = _fill(text)
    assert "ip-private" in _names(text, publish=True), text
    rendered = _render(ss.scan_text("docs/hosts.md", text + "\n", publish=True))
    assert "[ip-private]" in rendered and LAN not in rendered


@pytest.mark.parametrize("text", ["v1.2.3.4", "x1.2.3.4y", "1.2.3.4.5", "doc_192.0.2.10", "build_2026.10.15.1"])
def test_versions_and_documentation_ips_stay_quiet(text):
    assert not _names(text, publish=True) & {"ip-private", "ip-public", "ip-tailnet"}, text


def test_an_ip_joined_by_underscore_in_file_ref_and_tag_names():
    found = ss.path_findings(f"scans/nmap_{LAN}.xml", b"", None, publish=True)
    assert _detectors(found) == ["path:ip-private"] and LAN not in _render(found)
    for name in (f"refs/heads/fix_{LAN}", f"refs/heads/{LAN}_dc", f"refs/tags/rel_{LAN}"):
        found = ss.scan_ref_name(name, local=None, publish=True)
        assert _detectors(found) == ["ref:ip-private"] and LAN not in _render(found), name
    found = ss.scan_tag_name(f"rel_{LAN}", local=None, publish=True)
    assert _detectors(found) == ["ref:ip-private"] and LAN not in _render(found)


# --------------------------------------------------------------------------- #
# Ref names and binaries: detectors that are not judged are left out first
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,detector,value", [
    (f"refs/heads/token={TICKET}", "ref:psa-ticket-id", TICKET),
    (f"refs/heads/password={MAIL}", "ref:email-address", MAIL),
    ("refs/heads/" + fakes.rand("v6-ref-entropy", 27) + f"-{LAN}", "ref:ip-private", LAN),
])
def test_a_secret_detector_ref_names_do_not_judge_never_hides_a_never_public_value(name, detector, value):
    found = ss.scan_ref_name(name, local=None, publish=True)
    assert detector in _detectors(found) and value not in _render(found)


def test_find_hits_only_filters_before_overlaps_are_resolved():
    text = f"token={TICKET}"
    assert "psa-ticket-id" not in _names(text, publish=True)  # the assignment wins the overlap
    hits = sp.find_hits(text, publish=True, only=frozenset({"psa-ticket-id"}))
    assert [h.detector for h in hits] == ["psa-ticket-id"] and hits[0].value == TICKET
    # a check's sharper name counts: ip-address reports ip-private
    hits = sp.find_hits(f"gw {LAN}", publish=True, only=frozenset({"ip-private"}))
    assert [h.detector for h in hits] == ["ip-private"]
    assert sp.find_hits(f"gw {LAN}", publish=True, only=frozenset({"ip-public"})) == []


def test_binary_content_still_finds_token_shapes():
    token = "gh" + "p_" + fakes.rand("v6-bin-token", 36)
    data = b"\x00\x01\x02ELF" + bytes(range(256)) + b"\x00token: " + token.encode() + b"\x00" + bytes(64)
    found = ss.binary_findings("tools/agent.bin", data, publish=False, local=None)
    assert "github-token" in _detectors(found) and token not in _render(found)


# --------------------------------------------------------------------------- #
# commit-msg: only git's own scissors block
# --------------------------------------------------------------------------- #

_GIT_SCISSORS = ("{c} ------------------------ >8 ------------------------\n"
                 "{c} Do not modify or remove the line above.\n"
                 "{c} Everything below it will be ignored.\n")


@pytest.mark.parametrize("block,cut", [
    (_GIT_SCISSORS.format(c="#"), True),
    (_GIT_SCISSORS.format(c=";"), False),   # v8: ';' is git's only with core.commentChar=; (below)
    (_GIT_SCISSORS.format(c="#").split("\n", 1)[0] + "\n", False),     # the cut line alone
    ("# -------- >8 --------\n# Do not modify or remove the line above.\n"
     "# Everything below it will be ignored.\n", False),               # not git's line
    (_GIT_SCISSORS.format(c="#").replace("modify or remove", "touch"), False),
    ("# ------------------------ >8 ------------------------\n"
     "; Do not modify or remove the line above.\n"
     "; Everything below it will be ignored.\n", False),               # mixed comment strings
])
def test_only_gits_own_scissors_block_cuts_the_message(block, cut):
    # What follows is git's -v diff (v7: a block counts only when git's own
    # text follows it; see test_guardrails_v7).
    raw = f"subject\n\n{block}diff --git a/net.md b/net.md\n+gw {LAN}\n"
    kept = ss.message_file_text(raw, editor=True)
    assert (LAN not in kept) is cut
    assert LAN in ss.message_file_text(raw, editor=False)


def test_a_scissors_block_on_the_configured_comment_string_cuts():
    raw = f"subject\n\n{_GIT_SCISSORS.format(c=';')}diff --git a/net.md b/net.md\n+gw {LAN}\n"
    assert LAN not in ss.message_file_text(raw, editor=True, config=ss.MessageConfig((";",)))


# --------------------------------------------------------------------------- #
# Hooks in a throwaway clone
# --------------------------------------------------------------------------- #

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


def _remote_has(remote, ref: str) -> bool:
    return remote.git("rev-parse", "--verify", "-q", ref, check=False).returncode == 0


def _leak_branch(repo) -> str:
    """main pushed clean; branch 'leak' (a private IP, pushed with
    --no-verify, as before the strict checks) on top. Returns the leak sha."""
    assert repo.git("push", "-q", "origin", "main", check=False).returncode == 0
    repo.git("checkout", "-q", "-b", "leak")
    assert repo.commit("docs/net.md", f"gateway {LAN}\n", no_verify=True).returncode == 0
    repo.git("push", "-q", "--no-verify", "origin", "leak")
    return repo.git("rev-parse", "HEAD").stdout.strip()


@pytest.mark.parametrize("how", ["deleted", "force-pushed"])
def test_pre_push_rechecks_a_commit_the_remote_no_longer_holds(guarded, how):
    repo, remote = guarded
    _leak_branch(repo)
    main = repo.git("rev-parse", "main").stdout.strip()
    # Another clone cleans up; this clone's refs/remotes/origin/leak stays (no fetch --prune).
    if how == "deleted":
        remote.git("update-ref", "-d", "refs/heads/leak")
    else:
        remote.git("update-ref", "refs/heads/leak", main)
    assert repo.git("rev-parse", "--verify", "-q", "refs/remotes/origin/leak", check=False).returncode == 0
    proc = repo.git("push", "origin", "leak:refs/heads/again", check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "docs/net.md:1: [ip-private]" in out and LAN not in out
    assert not _remote_has(remote, "refs/heads/again")
    # what the remote really holds is still exempt: main moved to a commit it has
    assert repo.git("push", "-q", "origin", "main:refs/heads/copy", check=False).returncode == 0


def test_pre_push_still_skips_what_the_remote_holds_under_another_ref(guarded):
    repo, remote = guarded
    tip = _leak_branch(repo)
    repo.git("checkout", "-q", "main")
    repo.git("merge", "-q", "--ff-only", "leak")
    proc = repo.git("push", "-q", "origin", "main", check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert remote.git("rev-parse", "refs/heads/main").stdout.strip() == tip


def test_pre_push_asks_the_push_url_not_the_fetch_url(guarded, make_repo):
    repo, remote = guarded
    _leak_branch(repo)
    other = make_repo("other.git", bare=True)
    repo.git("config", "remote.origin.pushurl", str(other.path))  # tracking refs say "origin has it"
    proc = repo.git("push", "origin", "leak", check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "docs/net.md:1: [ip-private]" in out and LAN not in out
    assert not _remote_has(other, "refs/heads/leak")


def test_pre_push_without_a_listing_assumes_nothing_is_there(guarded, tmp_path):
    repo, remote = guarded
    leak = _leak_branch(repo)
    repo.git("checkout", "-q", "main")
    base = repo.git("rev-parse", "HEAD").stdout.strip()
    assert repo.commit("app/a.py", "x = 1\n").returncode == 0
    tip = repo.git("rev-parse", "HEAD").stdout.strip()
    zero = "0" * len(tip)
    hook = repo.path / ".githooks" / "pre-push"
    unreachable = str(tmp_path / "no-such-remote.git")

    def run(line: str) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(hook), "origin", unreachable], input=line + "\n",
                              cwd=repo.path, env=repo.env, capture_output=True, text=True)

    # an update: exactly <remote tip>..<local tip> (clean)
    proc = run(f"refs/heads/main {tip} refs/heads/main {base}")
    assert proc.returncode == 0 and "could not list" in proc.stderr, proc.stderr
    # a new ref: its whole history, the commit on 'leak' included
    proc = run(f"refs/heads/leak {leak} refs/heads/again {zero}")
    assert proc.returncode == 1 and "docs/net.md:1: [ip-private]" in proc.stdout + proc.stderr


def test_the_range_cli_takes_remote_tips(make_repo, tmp_path):
    repo = make_repo()
    repo.commit("a.py", "x = 1\n")
    base = repo.git("rev-parse", "HEAD").stdout.strip()
    repo.commit("docs/net.md", f"gw {LAN}\n")
    tip = repo.git("rev-parse", "HEAD").stdout.strip()
    tips = tmp_path / "ls-remote.txt"
    strict = ("--no-local-block", "--publish")
    tips.write_text(f"{tip}\trefs/heads/feature\n{base}\tHEAD\n" + "f" * 40 + "\trefs/heads/unknown\n")
    assert repo.scan("--range", tip, "--remote-tips", str(tips), *strict).returncode == 0
    tips.write_text(f"{base}\trefs/heads/main\n")
    proc = repo.scan("--range", tip, "--remote-tips", str(tips), *strict)
    assert proc.returncode == 1 and "docs/net.md:1: [ip-private]" in proc.stdout
    tips.write_text("")  # the remote holds nothing: the whole history
    assert repo.scan("--range", tip, "--remote-tips", str(tips), *strict).returncode == 1
    proc = repo.scan("--range", tip, "--remote", "origin", "--remote-tips", str(tips), *strict)
    assert proc.returncode == 2  # alternatives, not both


@pytest.mark.parametrize("kind", ["branch", "tag"])
def test_pre_push_refuses_an_underscore_joined_ip_in_a_ref_name(guarded, kind):
    repo, remote = guarded
    assert repo.commit("app/a.py", "x = 1\n").returncode == 0
    name = f"fix_{LAN}" if kind == "branch" else f"rel_{LAN}"
    if kind == "branch":
        repo.git("branch", name)
    else:
        repo.git("tag", "-a", name, "-m", "release")
    proc = repo.git("push", "origin", name, check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "[ref:ip-private]" in out and LAN not in out
    ref = f"refs/{'heads' if kind == 'branch' else 'tags'}/{name}"
    assert not _remote_has(remote, ref)
    if kind == "tag":  # the annotated tag records its name: a neutral refspec does not hide it
        proc = repo.git("push", "origin", f"refs/tags/{name}:refs/tags/v1", check=False)
        assert proc.returncode != 0 and "<tag-name>:0: [ref:ip-private]" in proc.stdout + proc.stderr


def test_pre_commit_refuses_an_underscore_joined_ip_in_a_file_name(guarded):
    repo, _ = guarded
    proc = repo.commit(f"scans/nmap_{LAN}.xml", "<nmaprun/>\n")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "[path:ip-private]" in out and LAN not in out


def _editor(tmp_path: Path, name: str, body: str) -> Path:
    script = tmp_path / name
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(0o755)
    return script


def test_commit_msg_checks_text_below_a_typed_scissors_line(guarded, tmp_path):
    repo, _ = guarded
    repo.write("app/b.py", "y = 2\n")
    repo.git("add", "app/b.py")
    typed = tmp_path / "typed.txt"
    typed.write_text("feat: b\n# ------------------------ >8 ------------------------\nhost " + LAN + "\n")
    editor = _editor(tmp_path, "typed.sh", f'cp "{typed}" "$1"\n')
    proc = subprocess.run(["git", "commit", "-q"], cwd=repo.path, env=dict(repo.env, GIT_EDITOR=str(editor)),
                          capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "[ip-private]" in out and LAN not in out


def test_commit_msg_cuts_the_diff_of_git_commit_verbose(guarded, tmp_path):
    repo, _ = guarded
    assert repo.commit("docs/net.md", f"gw {LAN}\n", no_verify=True).returncode == 0
    repo.write("docs/net.md", "gw 192.0.2.10\n")  # the -v diff shows the old line as removed
    repo.git("add", "docs/net.md")
    editor = _editor(tmp_path, "subject.sh", 'printf "docs: doc address\\n" | cat - "$1" > "$1.new" && mv "$1.new" "$1"\n')
    proc = subprocess.run(["git", "commit", "-q", "-v"], cwd=repo.path,
                          env=dict(repo.env, GIT_EDITOR=str(editor), LC_ALL="C"),
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert LAN not in repo.git("log", "-1", "--format=%B").stdout
