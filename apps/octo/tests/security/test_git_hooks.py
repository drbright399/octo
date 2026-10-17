""".githooks/pre-commit and .githooks/pre-push in a throwaway clone: a staged
fake key blocks the commit, a commit that skipped the hook is caught on push,
clean work goes through. The block list is always a synthetic one written into
the throwaway clone; never-public values are assembled at run time."""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

from apps.octo.tests.security import fakes

SECRET = fakes.rand("hook-secret", 32)
LEAK = f"client_secret = '{SECRET}'\n"


@pytest.fixture
def guarded(make_repo):
    """A clone with the guardrails installed and committed, and a bare remote."""
    remote = make_repo("remote.git", bare=True)
    repo = make_repo()
    repo.install_guardrails()
    repo.git("add", "-A")
    first = repo.git("commit", "-q", "-m", "guardrails", check=False)
    assert first.returncode == 0, first.stdout + first.stderr  # the scanner passes itself
    repo.git("remote", "add", "origin", str(remote.path))
    return repo, remote


def _count(repo) -> int:
    return int(repo.git("rev-list", "--count", "HEAD").stdout)


def _install(repo, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(repo.path / "scripts" / "install_hooks.sh"), *args],
                          cwd=repo.path, env=repo.env, capture_output=True, text=True)


def test_install_script_pins_the_hooks_into_the_git_directory(make_repo):
    repo = make_repo()
    repo.install_guardrails()
    proc = _install(repo)
    assert proc.returncode == 0, proc.stderr
    pinned = repo.path / ".git" / "athena-guardrails"
    hooks_path = Path(repo.git("config", "core.hooksPath").stdout.strip())
    assert hooks_path.resolve() == (pinned / "hooks").resolve()
    for hook in ("pre-commit", "commit-msg", "pre-push"):
        assert (pinned / "hooks" / hook).stat().st_mode & 0o111
    assert (pinned / "scripts" / "scan_sensitive.py").is_file()
    assert (pinned / "apps" / "octo" / "security" / "secret_patterns.py").is_file()


def test_install_script_refuses_to_downgrade_the_pinned_scanner(make_repo):
    repo = make_repo()
    repo.install_guardrails()
    assert _install(repo).returncode == 0
    pinned = repo.path / ".git" / "athena-guardrails" / "scripts" / "scan_sensitive.py"
    pinned.write_text(pinned.read_text().replace("GUARDRAILS_VERSION = ", "GUARDRAILS_VERSION = 9"))
    proc = _install(repo)
    assert proc.returncode == 1 and "not downgrading" in proc.stderr
    assert _install(repo, "--force").returncode == 0


@pytest.fixture
def pinned(make_repo):
    """A clone whose hooks are pinned by install_hooks.sh, a bare remote, and
    a branch 'old' that predates the guardrails (no .githooks, no scanner)."""
    remote = make_repo("remote.git", bare=True)
    repo = make_repo()
    repo.commit("README.md", "# widget\n")
    repo.git("branch", "old")
    repo.install_guardrails()
    repo.git("add", "-A")
    assert repo.git("commit", "-q", "-m", "guardrails", check=False).returncode == 0
    assert _install(repo).returncode == 0
    repo.git("remote", "add", "origin", str(remote.path))
    return repo, remote


def test_pinned_hooks_guard_a_branch_that_predates_them(pinned):
    repo, remote = pinned
    repo.git("checkout", "-q", "old")
    assert not (repo.path / ".githooks" / "pre-push").exists()
    proc = repo.commit("app/settings.py", LEAK)
    assert proc.returncode != 0 and "[secret-assignment]" in proc.stdout + proc.stderr
    assert repo.commit("app/settings.py", LEAK, no_verify=True).returncode == 0
    proc = repo.git("push", "-q", "origin", "old", check=False)
    assert proc.returncode != 0 and "[secret-assignment]" in proc.stdout + proc.stderr
    assert remote.git("rev-parse", "--verify", "-q", "refs/heads/old", check=False).returncode != 0


def test_pinned_hooks_guard_a_linked_worktree(pinned, tmp_path):
    repo, _ = pinned
    wt = tmp_path / "wt-old"
    repo.git("worktree", "add", "-q", str(wt), "old")
    (wt / "app").mkdir()
    (wt / "app" / "settings.py").write_text(LEAK)
    subprocess.run(["git", "add", "-A"], cwd=wt, env=repo.env, check=True)
    proc = subprocess.run(["git", "commit", "-q", "-m", "leak"], cwd=wt, env=repo.env,
                          capture_output=True, text=True)
    assert proc.returncode != 0 and "[secret-assignment]" in proc.stdout + proc.stderr


def test_commit_msg_hook_blocks_a_secret_in_the_message(pinned):
    repo, _ = pinned
    repo.write("app/a.py", "x = 1\n")
    repo.git("add", "-A")
    proc = repo.git("commit", "-q", "-m", f"rotate; old secret was {SECRET}", check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "<commit-message>" in out and SECRET not in out
    assert repo.git("commit", "-q", "-m", "add a", check=False).returncode == 0


def test_a_pinned_hook_says_when_the_branch_carries_a_newer_scanner(pinned):
    repo, _ = pinned
    scanner = repo.path / "scripts" / "scan_sensitive.py"
    scanner.write_text(scanner.read_text().replace("GUARDRAILS_VERSION = ", "GUARDRAILS_VERSION = 9"))
    proc = repo.commit("scripts/scan_sensitive.py", scanner.read_text(), message="bump")
    assert proc.returncode == 0 and "run scripts/install_hooks.sh" in proc.stderr


def test_pre_commit_blocks_a_staged_fake_key(guarded):
    repo, _ = guarded
    before = _count(repo)
    proc = repo.commit("app/settings.py", "DEBUG = False\n" + LEAK)
    assert proc.returncode != 0
    out = proc.stdout + proc.stderr
    assert "app/settings.py:2: [secret-assignment]" in out and SECRET not in out
    assert _count(repo) == before


def test_pre_commit_blocks_a_never_commit_file(guarded):
    repo, _ = guarded
    repo.write("vault/datto.env.gpg", "-----BEGIN PGP MESSAGE-----\n")
    repo.git("add", "-f", "vault/datto.env.gpg")
    proc = repo.git("commit", "-q", "-m", "vault", check=False)
    assert proc.returncode != 0
    assert "forbidden-file:encrypted-vault-file" in proc.stdout + proc.stderr


def test_pre_commit_passes_a_clean_commit(guarded):
    repo, _ = guarded
    before = _count(repo)
    assert repo.commit("app/settings.py", "DEBUG = False\n").returncode == 0
    assert _count(repo) == before + 1


def test_pre_push_catches_a_commit_that_skipped_the_hook(guarded):
    repo, remote = guarded
    assert repo.commit("app/clean.py", "x = 1\n").returncode == 0
    assert repo.commit("app/settings.py", LEAK, no_verify=True).returncode == 0
    proc = repo.git("push", "-q", "origin", "main", check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "app/settings.py:1: [secret-assignment]" in out and SECRET not in out
    assert remote.git("rev-parse", "--verify", "-q", "refs/heads/main", check=False).returncode != 0


def test_pre_push_passes_clean_work_and_scans_only_what_is_new(guarded):
    repo, remote = guarded
    assert repo.commit("app/a.py", "x = 1\n").returncode == 0
    assert repo.git("push", "-q", "origin", "main", check=False).returncode == 0
    assert repo.commit("app/b.py", "y = 2\n").returncode == 0
    assert repo.git("push", "-q", "origin", "main", check=False).returncode == 0
    # a new branch on a commit the remote already has sends nothing new
    repo.git("branch", "topic")
    assert repo.git("push", "-q", "origin", "topic", check=False).returncode == 0
    head = repo.git("rev-parse", "HEAD").stdout
    assert remote.git("rev-parse", "refs/heads/main").stdout == head


def test_pre_push_scans_a_force_push_over_an_unknown_tip(guarded):
    repo, _ = guarded
    assert repo.commit("app/settings.py", LEAK, no_verify=True).returncode == 0
    proc = repo.git("push", "-q", "--force", "origin", "main", check=False)
    assert proc.returncode != 0


# --- the pushed ref NAME ---------------------------------------------------- #
# A branch or tag name is as public as a file once it is on the remote. The
# term is assembled at runtime and checked case-insensitively in the output.
BLOCKED = "glo" + "bex"


def _block_term(repo) -> None:
    """A local-block file in the clone (never staged: the tests add by path)."""
    repo.write(".githooks/.local-block", f"# fixture term\n{BLOCKED}\n")


def _remote_has(remote, ref: str) -> bool:
    return remote.git("rev-parse", "--verify", "-q", ref, check=False).returncode == 0


@pytest.mark.parametrize("kind", ["branch", "tag"])
def test_pre_push_refuses_a_ref_name_with_a_local_block_term(guarded, kind):
    repo, remote = guarded
    _block_term(repo)
    assert repo.commit("app/a.py", "x = 1\n").returncode == 0
    name = f"{BLOCKED}-onboarding"
    repo.git(kind, name)
    proc = repo.git("push", "origin", name, check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "<ref-name>:0: [local-block]" in out and "neutral name" in out
    assert BLOCKED not in out.lower()  # the hook never echoes the name unmasked
    ref = f"refs/{'heads' if kind == 'branch' else 'tags'}/{name}"
    assert not _remote_has(remote, ref)


def test_pre_push_allows_the_same_work_under_a_neutral_remote_name(guarded):
    repo, remote = guarded
    _block_term(repo)
    assert repo.commit("app/a.py", "x = 1\n").returncode == 0
    repo.git("branch", f"{BLOCKED}-onboarding")
    proc = repo.git("push", "-q", "origin", f"{BLOCKED}-onboarding:refs/heads/onboarding",
                    check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _remote_has(remote, "refs/heads/onboarding")


def test_pre_push_refuses_a_token_shaped_ref_name(guarded):
    repo, remote = guarded
    token = "gh" + "p_" + fakes.rand("ref-token", 36)
    repo.git("branch", f"fix-{token}")
    proc = repo.git("push", "origin", f"fix-{token}", check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "[ref:github-token]" in out and token not in out
    assert not _remote_has(remote, f"refs/heads/fix-{token}")


def test_pre_push_never_refuses_deleting_a_badly_named_remote_ref(guarded):
    repo, remote = guarded
    _block_term(repo)
    name = f"{BLOCKED}-onboarding"
    repo.git("branch", name)
    repo.git("push", "-q", "--no-verify", "origin", name)  # how the name got there
    assert _remote_has(remote, f"refs/heads/{name}")
    proc = repo.git("push", "-q", "origin", "--delete", name, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not _remote_has(remote, f"refs/heads/{name}")


def test_pre_push_ref_name_check_fails_closed(guarded):
    repo, remote = guarded
    # A scanner that cannot check names (exit 2 = error) refuses the push.
    repo.write("scripts/scan_sensitive.py",
               "import sys\nsys.exit(2 if '--ref-name' in sys.argv else 0)\n")
    proc = repo.git("push", "origin", "main", check=False)
    assert proc.returncode != 0 and "could not be checked" in proc.stdout + proc.stderr
    assert not _remote_has(remote, "refs/heads/main")


def test_pre_push_refuses_a_line_without_a_remote_ref_name(guarded):
    # git always names the remote ref; a line without one is refused, not skipped.
    repo, remote = guarded
    sha = repo.git("rev-parse", "HEAD").stdout.strip()
    proc = subprocess.run(["bash", str(repo.path / ".githooks" / "pre-push"), "origin", str(remote.path)],
                          input=f"refs/heads/main {sha}\n", cwd=repo.path, env=repo.env,
                          capture_output=True, text=True)
    assert proc.returncode == 1 and "could not be checked" in proc.stderr


def test_pre_push_refuses_when_the_block_list_variable_names_a_missing_file(guarded, tmp_path):
    # A set-but-missing block list is an error (exit 2), never "no client terms".
    repo, remote = guarded
    env = dict(repo.env, SCAN_SENSITIVE_LOCAL_BLOCK=str(tmp_path / "missing-block-list"))

    def run(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", *args], cwd=repo.path, env=env, capture_output=True, text=True)

    proc = run("push", "origin", "main")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "does not exist" in out and "could not be checked" in out
    assert not _remote_has(remote, "refs/heads/main")
    repo.write("app/a.py", "x = 1\n")
    repo.git("add", "app/a.py")
    proc = run("commit", "-q", "-m", "add a")
    assert proc.returncode != 0 and "does not exist" in proc.stdout + proc.stderr


def _block_word(repo) -> None:
    """The term written with word boundaries, as most block-list lines are."""
    repo.write(".githooks/.local-block", f"# fixture term, word-bounded\n\\<{BLOCKED}\\>\n")


@pytest.mark.parametrize("name", [f"{BLOCKED}_onboarding", f"feat/{BLOCKED}2"])
def test_pre_push_refuses_a_word_bounded_term_joined_by_underscore_or_digits(guarded, name):
    repo, remote = guarded
    _block_word(repo)
    assert repo.commit("app/a.py", "x = 1\n").returncode == 0
    repo.git("branch", name)
    proc = repo.git("push", "origin", name, check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "<ref-name>:0: [local-block]" in out
    assert BLOCKED not in out.lower()
    assert not _remote_has(remote, f"refs/heads/{name}")


@pytest.mark.parametrize("nested", [False, True])
def test_pre_push_refuses_an_annotated_tag_whose_recorded_name_is_blocked(guarded, nested):
    # The tag object carries "tag <name>": a neutral refspec does not hide it.
    repo, remote = guarded
    _block_term(repo)
    assert repo.commit("app/a.py", "x = 1\n").returncode == 0
    local = f"{BLOCKED}-v1"
    repo.git("tag", "-a", local, "-m", "release one")
    if nested:
        repo.git("tag", "-a", "outer", local, "-m", "release one again")
        local = "outer"
    proc = repo.git("push", "origin", f"refs/tags/{local}:refs/tags/v1", check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "<tag-name>:0: [local-block]" in out and "re-create the tag" in out
    assert BLOCKED not in out.lower()
    assert not _remote_has(remote, "refs/tags/v1")


def test_pre_push_allows_a_lightweight_tag_under_a_neutral_name(guarded):
    # A lightweight tag is only a ref: renamed by the refspec, its local name never leaves.
    repo, remote = guarded
    _block_term(repo)
    assert repo.commit("app/a.py", "x = 1\n").returncode == 0
    repo.git("tag", f"{BLOCKED}-v1")
    repo.git("tag", "-a", "v2", "-m", "release two")
    for spec in (f"refs/tags/{BLOCKED}-v1:refs/tags/v1", "refs/tags/v2"):
        proc = repo.git("push", "-q", "origin", spec, check=False)
        assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _remote_has(remote, "refs/tags/v1") and _remote_has(remote, "refs/tags/v2")


# --- guardrails v5 (2026-10-15 review round) -------------------------------- #
# Values that are never public are assembled at runtime: a LAN address, a real
# e-mail domain, a ticket number (only T20000101.0001 may appear literally).
LAN = fakes.ip(10, 20, 30, 40)
TICKET = fakes.ticket(2026, 10, 15, 6)
MAIL = "ops" + "@" + "corp-mail.co"


def test_pre_push_does_not_recheck_commits_the_remote_already_has(guarded, make_repo):
    repo, remote = guarded
    _block_term(repo)
    assert repo.git("push", "-q", "origin", "main", check=False).returncode == 0
    repo.git("checkout", "-q", "-b", "feature")
    # Pushed before the strict checks existed (simulated with --no-verify),
    # cleaned up since: the final tree is clean, the history is not.
    assert repo.commit("docs/net.md", f"gateway {LAN}\n", no_verify=True).returncode == 0
    assert repo.commit("docs/net.md", "gateway 192.0.2.10\n").returncode == 0
    repo.git("push", "-q", "--no-verify", "origin", "feature")
    # main fast-forwards to commits origin already holds under another branch
    repo.git("checkout", "-q", "main")
    repo.git("merge", "-q", "--ff-only", "feature")
    proc = repo.git("push", "-q", "origin", "main", check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    tip = repo.git("rev-parse", "HEAD").stdout
    assert remote.git("rev-parse", "refs/heads/main").stdout == tip
    # a brand-new commit on top is still checked, and only it
    assert repo.commit("docs/new.md", f"gw {LAN}\n", no_verify=True).returncode == 0
    proc = repo.git("push", "origin", "main", check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "docs/new.md:1: [ip-private]" in out
    assert "docs/net.md" not in out and LAN not in out
    # another remote (a bare URL) holds none of it: every commit is checked there
    other = make_repo("other.git", bare=True)
    repo.git("reset", "-q", "--hard", "HEAD~1")
    proc = repo.git("push", str(other.path), "main", check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "docs/net.md:1: [ip-private]" in out and LAN not in out
    assert other.git("rev-parse", "--verify", "-q", "refs/heads/main", check=False).returncode != 0


@pytest.mark.parametrize("name,detector,value", [
    (f"fix/{LAN}-gw", "ref:ip-private", LAN),
    (f"feat/{MAIL}", "ref:email-address", MAIL),
    (f"fix/{TICKET.lower()}-printer", "ref:psa-ticket-id", TICKET.lower()),
])
def test_pre_push_refuses_a_never_public_value_in_a_ref_name(guarded, name, detector, value):
    repo, remote = guarded
    _block_term(repo)  # the synthetic block list is honoured alongside
    assert repo.commit("app/a.py", "x = 1\n").returncode == 0
    repo.git("branch", name)
    proc = repo.git("push", "origin", name, check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and f"<ref-name>:0: [{detector}]" in out and "neutral name" in out
    assert value not in out.lower()  # the hook never echoes the name unmasked
    assert not _remote_has(remote, f"refs/heads/{name}")
    proc = repo.git("push", "-q", "origin", f"{name}:refs/heads/neutral", check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_pre_push_passes_ordinary_and_documentation_ref_names(guarded):
    repo, remote = guarded
    assert repo.commit("app/a.py", "x = 1\n").returncode == 0
    repo.git("tag", "-a", "v1.2.3.4", "-m", "release")
    repo.git("branch", "fix/192.0.2.10-gw")
    for spec in ("refs/tags/v1.2.3.4", "fix/192.0.2.10-gw", "main"):
        proc = repo.git("push", "-q", "origin", spec, check=False)
        assert proc.returncode == 0, (spec, proc.stdout + proc.stderr)


def test_pre_push_refuses_an_annotated_tag_whose_recorded_name_carries_an_ip(guarded):
    repo, remote = guarded
    assert repo.commit("app/a.py", "x = 1\n").returncode == 0
    repo.git("tag", "-a", f"gw-{LAN}", "-m", "release")
    proc = repo.git("push", "origin", f"refs/tags/gw-{LAN}:refs/tags/v1", check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "<tag-name>:0: [ref:ip-private]" in out and LAN not in out
    assert not _remote_has(remote, "refs/tags/v1")


def test_commit_msg_checks_hash_lines_git_keeps(guarded):
    repo, _ = guarded
    repo.write("app/a.py", "x = 1\n")
    repo.git("add", "app/a.py")
    proc = repo.git("commit", "-q", "-m", f"feat: d\n\n# Notes\n# gw {LAN}", check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "<commit-message>:4: [ip-private]" in out and LAN not in out
    assert repo.git("commit", "-q", "-m", "feat: d\n\n# Notes\n# gw 192.0.2.10", check=False).returncode == 0
    assert "# Notes" in repo.git("log", "-1", "--format=%B").stdout  # git kept the '#' lines


def test_commit_msg_ignores_the_editor_template_git_strips(guarded, tmp_path):
    repo, _ = guarded
    (repo.path / f"gw-{LAN}.txt").write_text("untracked: listed in the editor template\n")
    repo.write("app/b.py", "y = 2\n")
    repo.git("add", "app/b.py")
    editor = tmp_path / "editor.sh"
    editor.write_text('#!/bin/sh\nprintf "feat: add b\\n" | cat - "$1" > "$1.new" && mv "$1.new" "$1"\n')
    editor.chmod(0o755)
    env = dict(repo.env, GIT_EDITOR=str(editor))
    proc = subprocess.run(["git", "commit", "-q"], cwd=repo.path, env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    message = repo.git("log", "-1", "--format=%B").stdout
    assert message.startswith("feat: add b") and LAN not in message


def test_commit_msg_refuses_a_real_ticket_number_but_not_the_fixture(guarded):
    repo, _ = guarded
    proc = repo.git("commit", "-q", "--allow-empty", "-m", f"fix: printer ({TICKET})", check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "<commit-message>:1: [psa-ticket-id]" in out and TICKET not in out
    assert "allow[psa-ticket-id]" in out  # the report says how to resolve it
    proc = repo.git("commit", "-q", "--allow-empty", "-m", "fix: printer (T20000101.0001)", check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_pre_commit_refuses_a_password_on_a_command_line(guarded):
    repo, _ = guarded
    password = "Q" + fakes.rand("hook-cli-pw", 8) + "#7k"
    proc = repo.commit("ops/mount.cmd", "net use \\\\" + LAN + "\\c$ /user:admin " + password + "\n")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "ops/mount.cmd:1: [cli-password]" in out
    assert password not in out and LAN not in out


def _hooks_path(repo) -> Path:
    return Path(repo.git("config", "core.hooksPath").stdout.strip())


def test_install_swaps_the_pinned_copy_through_a_symlink(make_repo):
    repo = make_repo()
    repo.install_guardrails()
    git_dir = repo.path / ".git"
    pinned = git_dir / "athena-guardrails"
    versions = []
    for _ in range(3):
        proc = _install(repo)
        assert proc.returncode == 0, proc.stderr
        assert pinned.is_symlink() and _hooks_path(repo) == pinned / "hooks"
        versions.append(os.readlink(pinned))
        assert versions[-1].startswith("athena-guardrails.v")
        assert (pinned / "hooks" / "pre-commit").stat().st_mode & 0o111
    assert len(set(versions)) == 3
    # the copy just replaced is kept (a hook may still be running from it); older ones go
    assert (git_dir / versions[1]).is_dir() and not (git_dir / versions[0]).exists()
    proc = repo.commit("app/settings.py", LEAK)
    assert proc.returncode != 0 and "[secret-assignment]" in proc.stdout + proc.stderr


def test_install_migrates_a_plain_directory_install(make_repo):
    repo = make_repo()
    repo.install_guardrails()
    git_dir = repo.path / ".git"
    old = git_dir / "athena-guardrails"
    shutil.copytree(repo.path / ".githooks", old / "hooks")  # the pre-v5 layout
    for rel in ("scripts", "apps"):
        shutil.copytree(repo.path / rel, old / rel)
    repo.git("config", "core.hooksPath", str(old / "hooks"))
    proc = _install(repo)
    assert proc.returncode == 0, proc.stderr
    assert old.is_symlink() and (old / "hooks" / "pre-push").is_file()
    assert _hooks_path(repo) == old / "hooks"
    assert not [p.name for p in git_dir.iterdir() if ".retired." in p.name or ".link." in p.name]


def test_install_never_leaves_the_hooks_path_missing(make_repo):
    # Before v5 the pinned directory was removed and then replaced: for a
    # moment core.hooksPath named nothing, and git ran no hooks at all.
    repo = make_repo()
    repo.install_guardrails()
    assert _install(repo).returncode == 0
    hooks = _hooks_path(repo)
    missing: list[float] = []
    stop = threading.Event()

    def watch() -> None:
        while not stop.is_set():
            if not (hooks / "pre-commit").is_file():
                missing.append(time.monotonic())

    watcher = threading.Thread(target=watch)
    watcher.start()
    try:
        for _ in range(5):
            assert _install(repo).returncode == 0
    finally:
        stop.set()
        watcher.join()
    assert missing == []
