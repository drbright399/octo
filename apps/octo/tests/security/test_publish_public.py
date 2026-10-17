"""scripts/publish_public.sh: allowlist export, replacement map, the --publish
scan that refuses, the single noreply orphan commit (--out) and the one
commit on top of a public clone's main (--onto); nothing is ever pushed."""
from __future__ import annotations

import subprocess

import pytest

from apps.octo.tests.security import fakes
from apps.octo.tests.security.conftest import REPO_ROOT, Repo


# The publish identity is required (no default): a fictional, ID-based GitHub
# noreply address, the only form the script accepts.
_ID_NAME = "Example Maintainer"
_ID_EMAIL = "12345678+example-maintainer@users.noreply.github.com"


def _env(repo):
    return dict(repo.env, PUBLISH_AUTHOR_NAME=_ID_NAME, PUBLISH_AUTHOR_EMAIL=_ID_EMAIL)

PUBLISH = REPO_ROOT / "scripts" / "publish_public.sh"
SECRET = fakes.rand("publish-secret", 32)


@pytest.fixture
def source(make_repo, tmp_path):
    repo = make_repo("source")
    repo.write("README.md", "# Widget\nPublic readme for the Zebra Clinic build.\n")
    repo.write("src/app.py", "def main():\n    return 'ok'\n")
    repo.write("src/zebra_clinic_adapter.py", "NAME = 'Zebra Clinic'\n")
    repo.write("docs/internal/runbook.md", "internal only\n")
    repo.write("docs/notes.md", "not in the allowlist\n")
    repo.git("add", "-A")
    repo.git("commit", "-q", "-m", "source")
    allow = tmp_path / "allowlist.txt"
    allow.write_text("# test allowlist\nREADME.md\nsrc/\ndocs/**\n!docs/notes.md\n")
    block = tmp_path / "local-block"
    block.write_text("Zebra Clinic\nzebra_clinic\n")
    mapping = tmp_path / "publish-map"
    mapping.write_text("# real => neutral\nZebra Clinic => Example Clinic\n"
                       "zebra_clinic => example_clinic\n")
    return repo, allow, block, mapping


def _publish(repo, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(PUBLISH), "--repo", str(repo.path), *args],
                          cwd=repo.path, env=_env(repo), capture_output=True, text=True)


def test_dry_run_lists_only_allowlisted_files(source):
    repo, allow, block, mapping = source
    proc = _publish(repo, "--dry-run", "--allowlist", str(allow), "--local-block", str(block),
                    "--map", str(mapping))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    listed = [line.strip() for line in proc.stdout.splitlines() if line.startswith("  ")]
    assert listed == ["README.md", "src/app.py", "src/example_clinic_adapter.py"]
    assert "hard-excluded (allowlisted, never published): docs/internal/runbook.md" in proc.stderr
    assert "Scan: clean" in proc.stdout
    assert int(repo.git("rev-list", "--count", "--all").stdout) == 1  # nothing written to the source


def test_dry_run_refuses_a_local_term_the_map_does_not_cover(source):
    repo, allow, block, _ = source
    proc = _publish(repo, "--dry-run", "--allowlist", str(allow), "--local-block", str(block),
                    "--map", str(block.parent / "no-map"))
    assert proc.returncode == 1
    assert "[local-block]" in proc.stdout and "would REFUSE" in proc.stderr
    assert "Zebra Clinic" not in proc.stdout  # findings are masked


def test_dry_run_refuses_a_secret(source):
    repo, allow, block, mapping = source
    repo.write("src/settings.py", f"client_secret = '{SECRET}'\n")
    repo.git("add", "-A")
    repo.git("commit", "-q", "-m", "oops")
    proc = _publish(repo, "--dry-run", "--allowlist", str(allow), "--local-block", str(block),
                    "--map", str(mapping))
    assert proc.returncode == 1
    assert "src/settings.py:1: [secret-assignment]" in proc.stdout and SECRET not in proc.stdout


def test_publish_makes_one_noreply_orphan_commit_and_never_pushes(source, tmp_path):
    repo, allow, block, mapping = source
    out = tmp_path / "public"
    proc = _publish(repo, "--allowlist", str(allow), "--local-block", str(block),
                    "--map", str(mapping), "--out", str(out),
                    "--remote-url", "git@github.com:example/widget.git")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    git = ["git", "-C", str(out)]

    def run(*args: str) -> str:
        return subprocess.run(git + list(args), env=repo.env, capture_output=True,
                              text=True, check=True).stdout

    assert run("rev-list", "--count", "--all").strip() == "1"
    assert run("log", "-1", "--format=%an <%ae>|%cn <%ce>|%P").strip() == (
        f"{_ID_NAME} <{_ID_EMAIL}>|"
        f"{_ID_NAME} <{_ID_EMAIL}>|")  # no parent: an orphan
    body = run("log", "-1", "--format=%B")
    assert body.strip().startswith("Public snapshot") and ":" not in body  # no trailers
    assert run("ls-files").split() == ["README.md", "src/app.py", "src/example_clinic_adapter.py"]
    assert "Example Clinic" in (out / "README.md").read_text()
    assert run("remote").strip() == ""  # nothing to push to: a human pushes after review
    assert "NOT pushed" in proc.stdout
    assert f'git -C "{out}" push git@github.com:example/widget.git main' in proc.stdout
    assert int(repo.git("rev-list", "--count", "--all").stdout) == 1


def test_publish_refuses_and_leaves_nothing_behind(source, tmp_path):
    repo, allow, block, _ = source
    out = tmp_path / "public"
    proc = _publish(repo, "--allowlist", str(allow), "--local-block", str(block),
                    "--map", str(tmp_path / "no-map"), "--out", str(out))
    assert proc.returncode == 1 and "REFUSED" in proc.stderr
    assert not out.exists()


def test_publish_requires_the_local_terms_file(source, tmp_path):
    repo, allow, _, mapping = source
    proc = _publish(repo, "--dry-run", "--allowlist", str(allow), "--map", str(mapping))
    assert proc.returncode == 2 and "local-block" in proc.stderr


def test_publish_rejects_an_identity_that_is_not_noreply(source, tmp_path):
    repo, allow, block, mapping = source
    env = dict(repo.env, PUBLISH_AUTHOR_EMAIL="alice@example.com")
    proc = subprocess.run(["bash", str(PUBLISH), "--repo", str(repo.path), "--allowlist", str(allow),
                           "--local-block", str(block), "--map", str(mapping),
                           "--out", str(tmp_path / "public")],
                          env=env, capture_output=True, text=True)
    assert proc.returncode == 2 and "noreply" in proc.stderr


# --------------------------------------------------------------------------- #
# Red-team round 1: UTF-16 text, binary files, the snapshot's metadata
# --------------------------------------------------------------------------- #

def _commit_all(repo, message: str) -> None:
    repo.git("add", "-A")
    repo.git("commit", "-q", "-m", message)


def test_utf16_text_is_mapped_in_its_own_encoding_and_scanned(source, tmp_path):
    repo, allow, block, mapping = source
    ps1 = "# notes for the Zebra Clinic agent\r\nGet-Service | Format-List\r\n"
    (repo.path / "src" / "notes.ps1").write_bytes(b"\xff\xfe" + ps1.encode("utf-16-le"))
    _commit_all(repo, "ps1")
    refused = _publish(repo, "--dry-run", "--allowlist", str(allow), "--local-block", str(block),
                       "--map", str(tmp_path / "no-map"))
    assert refused.returncode == 1 and "src/notes.ps1:1: [local-block]" in refused.stdout
    out = tmp_path / "public"
    proc = _publish(repo, "--allowlist", str(allow), "--local-block", str(block),
                    "--map", str(mapping), "--out", str(out))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = (out / "src" / "notes.ps1").read_bytes()
    assert data.startswith(b"\xff\xfe")
    assert data[2:].decode("utf-16-le") == ps1.replace("Zebra Clinic", "Example Clinic")


def test_publish_refuses_a_binary_that_is_not_an_image_or_a_font(source):
    repo, allow, block, mapping = source
    (repo.path / "src" / "agent.bin").write_bytes(b"\x7fELF\x02\x01\x01\x00" + bytes(range(256)))
    (repo.path / "src" / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(256)))
    _commit_all(repo, "binaries")
    proc = _publish(repo, "--dry-run", "--allowlist", str(allow), "--local-block", str(block),
                    "--map", str(mapping))
    assert proc.returncode == 1 and "src/agent.bin:0: [binary-file]" in proc.stdout
    assert "src/logo.png:" not in proc.stdout


@pytest.mark.parametrize("env,expected", [
    ({"PUBLISH_AUTHOR_EMAIL": "rick.noreply@" + "clientcorp.com"}, "ID-based GitHub noreply address"),
    ({"PUBLISH_AUTHOR_EMAIL": "4242+zebra-clinic@users.noreply.github.com"}, "local-block term"),
    ({"PUBLISH_AUTHOR_EMAIL": "noreply@users.noreply.github.com"}, "ID-based GitHub noreply address"),
    ({"PUBLISH_AUTHOR_EMAIL": ""}, "there is no default"),
    ({"PUBLISH_AUTHOR_NAME": ""}, "there is no default"),
    ({"PUBLISH_AUTHOR_NAME": "Zebra Clinic Bot"}, "local-block term"),
    ({"PUBLISH_AUTHOR_NAME": "Alice Example"}, "operator's own git user.name"),
    ({"PUBLISH_AUTHOR_NAME": "Bot <x@y>"}, "may only use"),
])
def test_publish_identity_must_be_neutral(source, tmp_path, env, expected):
    repo, allow, block, mapping = source
    block.write_text(block.read_text() + "zebra-clinic\n")
    repo.git("config", "user.name", "Alice Example")
    proc = subprocess.run(["bash", str(PUBLISH), "--repo", str(repo.path), "--allowlist", str(allow),
                           "--local-block", str(block), "--map", str(mapping),
                           "--out", str(tmp_path / "public")],
                          env=dict(_env(repo), **env), capture_output=True, text=True)
    assert proc.returncode == 2 and expected in proc.stderr, proc.stderr
    assert not (tmp_path / "public").exists()


def test_the_snapshot_is_dated_in_utc(source, tmp_path):
    repo, allow, block, mapping = source
    out = tmp_path / "public"
    proc = subprocess.run(["bash", str(PUBLISH), "--repo", str(repo.path), "--allowlist", str(allow),
                           "--local-block", str(block), "--map", str(mapping), "--out", str(out)],
                          env=dict(_env(repo), TZ="America/Chicago"), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    raw = subprocess.run(["git", "-C", str(out), "cat-file", "commit", "HEAD"], env=repo.env,
                         capture_output=True, text=True, check=True).stdout
    author = next(line for line in raw.splitlines() if line.startswith("author "))
    committer = next(line for line in raw.splitlines() if line.startswith("committer "))
    assert author.endswith(" +0000") and committer.endswith(" +0000")


# --------------------------------------------------------------------------- #
# --onto: the next re-publish is one normal commit on top of the public main
# --------------------------------------------------------------------------- #

PUBLIC_IDENTITY = f"{_ID_NAME} <{_ID_EMAIL}>"


@pytest.fixture
def public_clone(source, make_repo, tmp_path):
    """A fake public repository seeded by the first (orphan) publish, and a
    clone of it as an operator would make one: (clone, remote)."""
    repo, allow, block, mapping = source
    first = tmp_path / "first"
    proc = _publish(repo, "--allowlist", str(allow), "--local-block", str(block),
                    "--map", str(mapping), "--out", str(first))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    remote = make_repo("public.git", bare=True)
    subprocess.run(["git", "-C", str(first), "push", "-q", str(remote.path), "main"],
                   env=repo.env, capture_output=True, check=True)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(remote.path), str(clone)],
                   env=repo.env, capture_output=True, check=True)
    return Repo(clone, repo.env), remote


def _onto(source, clone, *args: str, env=None, mapping=None) -> subprocess.CompletedProcess:
    repo, allow, block, default_map = source
    return subprocess.run(
        ["bash", str(PUBLISH), "--repo", str(repo.path), "--allowlist", str(allow),
         "--local-block", str(block), "--map", str(mapping or default_map),
         "--onto", str(clone.path), *args],
        cwd=repo.path, env=dict(_env(repo), **(env or {})), capture_output=True, text=True)


def _files(path) -> dict[str, bytes]:
    """Every file under ``path``, .git included: refs, index, objects."""
    return {str(p.relative_to(path)): p.read_bytes() for p in path.rglob("*") if p.is_file()}


def _head(repo) -> str:
    return repo.git("rev-parse", "HEAD").stdout.strip()


def _next_source_commit(repo) -> None:
    repo.write("README.md", "# Widget\nUpdated readme for the Zebra Clinic build.\n")
    repo.write("src/feature.py", "VALUE = 1\n")
    repo.git("rm", "-q", "src/app.py")
    _commit_all(repo, "next")


def test_onto_adds_one_commit_whose_tree_is_the_export(source, public_clone):
    repo = source[0]
    clone, remote = public_clone
    first = _head(clone)
    _next_source_commit(repo)
    proc = _onto(source, clone, "--remote-url", "git@github.com:example/widget.git",
                 env={"TZ": "America/Chicago"})
    assert proc.returncode == 0, proc.stdout + proc.stderr

    # One new commit on main, its only parent the public main it started from.
    assert clone.git("symbolic-ref", "--short", "HEAD").stdout.strip() == "main"
    assert clone.git("rev-list", "--count", "HEAD").stdout.strip() == "2"
    assert clone.git("log", "-1", "--format=%P").stdout.strip() == first
    # Its tree is exactly the export: mapped, the deleted file gone, nothing else.
    assert clone.git("ls-files").stdout.split() == [
        "README.md", "src/example_clinic_adapter.py", "src/feature.py"]
    assert (clone.path / "README.md").read_text() == (
        "# Widget\nUpdated readme for the Example Clinic build.\n")
    assert not (clone.path / "src" / "app.py").exists()
    assert clone.git("status", "--porcelain", "--untracked-files=all").stdout == ""
    # Neutral identity, UTC dates, no trailers.
    assert clone.git("log", "-1", "--format=%an <%ae>|%cn <%ce>").stdout.strip() == (
        f"{PUBLIC_IDENTITY}|{PUBLIC_IDENTITY}")
    raw = clone.git("cat-file", "commit", "HEAD").stdout
    header, _, body = raw.partition("\n\n")
    assert "\ngpgsig " not in header
    for line in header.splitlines():
        if line.startswith(("author ", "committer ")):
            assert line.endswith(" +0000"), line
    assert body.startswith("Public snapshot ") and ":" not in body
    # Never pushed; the removal is listed; the push is a plain fast-forward.
    assert remote.git("rev-parse", "main").stdout.strip() == first
    assert "NOT pushed" in proc.stdout and "1 added, 1 changed, 1 removed" in proc.stdout
    assert "removed (on the public main, not in this export" in proc.stdout
    assert "\n    src/app.py\n" in proc.stdout
    clone_dir = clone.path.resolve()
    assert f'git -C "{clone_dir}" push git@github.com:example/widget.git main' in proc.stdout
    assert "--force" not in proc.stdout and int(repo.git("rev-list", "--count", "--all").stdout) == 2

    # The operator pushes it; the next publish stacks on top again.
    clone.git("push", "-q", "origin", "main")
    second = _head(clone)
    repo.write("src/feature.py", "VALUE = 2\n")
    _commit_all(repo, "again")
    proc = _onto(source, clone)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert clone.git("rev-list", "--count", "HEAD").stdout.strip() == "3"
    assert clone.git("log", "-1", "--format=%P").stdout.strip() == second
    assert "0 added, 1 changed, 0 removed" in proc.stdout and "removed (" not in proc.stdout
    assert f'git -C "{clone_dir}" push origin main' in proc.stdout
    assert remote.git("rev-parse", "main").stdout.strip() == second


def test_onto_tree_keeps_files_the_exported_gitignore_names(source, public_clone):
    """The tree is the export, not what a .gitignore in it would let through."""
    repo = source[0]
    clone, _ = public_clone
    repo.write("src/.gitignore", "*.log\n")
    repo.write("src/sample.log", "synthetic sample line\n")
    repo.git("add", "-f", "src/.gitignore", "src/sample.log")
    repo.git("commit", "-q", "-m", "sample")
    proc = _onto(source, clone)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    tracked = clone.git("ls-files").stdout.split()
    assert "src/.gitignore" in tracked and "src/sample.log" in tracked
    assert clone.git("status", "--porcelain", "--untracked-files=all").stdout == ""


def test_onto_dry_run_shows_the_change_and_writes_nothing(source, public_clone):
    repo = source[0]
    clone, _ = public_clone
    _next_source_commit(repo)
    before = _files(clone.path)
    proc = _onto(source, clone, "--dry-run")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "  src/feature.py\n" in proc.stdout and "Scan: clean" in proc.stdout
    assert "1 added, 1 changed, 1 removed" in proc.stdout and "\n    src/app.py\n" in proc.stdout
    assert _files(clone.path) == before


def test_onto_with_nothing_new_commits_nothing(source, public_clone):
    clone, _ = public_clone
    before = _files(clone.path)
    proc = _onto(source, clone)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Nothing to publish" in proc.stdout
    assert _files(clone.path) == before


def test_onto_refused_scan_leaves_the_clone_untouched(source, public_clone, tmp_path):
    repo = source[0]
    clone, _ = public_clone
    _next_source_commit(repo)
    before = _files(clone.path)
    proc = _onto(source, clone, mapping=tmp_path / "no-map")  # the client name stays: refuse
    assert proc.returncode == 1 and "REFUSED" in proc.stderr and "is as it was" in proc.stderr
    assert "[local-block]" in proc.stdout and "Zebra Clinic" not in proc.stdout
    assert _files(clone.path) == before


def test_onto_refusal_at_the_commit_rescan_leaves_the_clone_untouched(source, public_clone):
    """The export is clean but the commit is not (here: its message holds a
    local term): refused after the commit was built, before the clone moved."""
    repo, _, block, _ = source
    clone, _ = public_clone
    _next_source_commit(repo)
    block.write_text(block.read_text() + "Public snapshot\n")
    before = _files(clone.path)
    proc = _onto(source, clone)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "did not re-scan clean" in proc.stderr and "is as it was" in proc.stderr
    # a finding in the message, not a scanner error
    assert "<commit-message>" in proc.stdout and "[local-block]" in proc.stdout
    assert _files(clone.path) == before  # no ref, no index, no object written


# What a commit this script makes looks like (identity, UTC dates). The git
# identity comes from these variables: they override any `-c user.name`.
_SNAPSHOT = {
    "GIT_AUTHOR_NAME": _ID_NAME, "GIT_AUTHOR_EMAIL": _ID_EMAIL,
    "GIT_COMMITTER_NAME": _ID_NAME, "GIT_COMMITTER_EMAIL": _ID_EMAIL,
    "GIT_AUTHOR_DATE": "@946684800 +0000", "GIT_COMMITTER_DATE": "@946684800 +0000",
}
_SNAPSHOT_MESSAGE = "Public snapshot 2000-01-01"


def _as(clone, **env: str):
    """The clone, with git run under ``env`` (the snapshot shape by default)."""
    return Repo(clone.path, dict(clone.env, **dict(_SNAPSHOT, **env)))


def _changed_in_place(message: str = _SNAPSHOT_MESSAGE, **env: str):
    """A commit on the public main that differs from one this script makes
    only in what ``message`` / ``env`` change (pushed, so the clone is at its
    upstream)."""
    def setup(clone):
        clone.write("HOTFIX.md", "edited on the hosting site\n")
        clone.git("add", "-A")
        _as(clone, **env).git("commit", "-q", "--cleanup=verbatim", "-m", message)
        clone.git("push", "-q", "origin", "main")
    return setup


def _merged_in_place(clone):
    """A merge commit on the public main, otherwise shaped like a snapshot."""
    snap = _as(clone)
    clone.git("switch", "-q", "-c", "side")
    clone.write("SIDE.md", "side\n")
    clone.git("add", "-A")
    snap.git("commit", "-q", "-m", _SNAPSHOT_MESSAGE)
    clone.git("switch", "-q", "main")
    clone.write("MAIN.md", "main\n")
    clone.git("add", "-A")
    snap.git("commit", "-q", "-m", _SNAPSHOT_MESSAGE)
    snap.git("merge", "-q", "--no-ff", "-m", _SNAPSHOT_MESSAGE, "side")
    clone.git("branch", "-q", "-D", "side")
    clone.git("push", "-q", "origin", "main")


def _tag_shadows_main(clone):
    """A foreign commit on main, and a local tag named "main" on the clean
    commit before it (that would shadow the branch in `git log main`): the
    ambiguous name is refused before any history is read."""
    _changed_in_place("hotfix")(clone)
    clone.git("tag", "main", "HEAD~1")


@pytest.mark.parametrize("setup,expected", [
    (lambda c: c.write("notes.txt", "scratch\n"), "modified or untracked files"),
    (lambda c: c.write("README.md", "edited by hand\n"), "modified or untracked files"),
    (lambda c: c.git("switch", "-q", "-c", "feature"), "is not on main"),
    (lambda c: (c.write("x.md", "x\n"), c.git("add", "x.md"),
                _as(c).git("commit", "-q", "-m", _SNAPSHOT_MESSAGE)), "not at its upstream"),
    (lambda c: c.git("branch", "-q", "--unset-upstream"), "has no upstream"),
    # Each differs from a script-made commit in one property only.
    (_changed_in_place(GIT_AUTHOR_EMAIL="alice@example.com",
                       GIT_COMMITTER_EMAIL="alice@example.com"),
     "a commit this script did not make"),
    (_changed_in_place("Bump a dependency"), "a commit this script did not make"),
    (_changed_in_place(_SNAPSHOT_MESSAGE + "\n\nwith a body"), "a commit this script did not make"),
    (_changed_in_place(_SNAPSHOT_MESSAGE + "\n\nSigned-off-by: Bot <bot@users.noreply.github.com>"),
     "a commit this script did not make"),
    # a web edit: the author is a user, the committer the hosting site
    (_changed_in_place(GIT_COMMITTER_NAME="Bot", GIT_COMMITTER_EMAIL="bot@users.noreply.github.com"),
     "a commit this script did not make"),
    (_changed_in_place(GIT_AUTHOR_DATE="@946684800 -0500", GIT_COMMITTER_DATE="@946684800 -0500"),
     "a commit this script did not make"),
    (_merged_in_place, "a commit this script did not make"),
    (_tag_shadows_main, "is not on main"),
])
def test_onto_refuses_a_clone_that_is_not_a_clean_public_main(source, public_clone, setup,
                                                              expected):
    repo = source[0]
    clone, _ = public_clone
    _next_source_commit(repo)
    setup(clone)
    head = _head(clone)
    before = _files(clone.path)
    proc = _onto(source, clone)
    assert proc.returncode == 2 and expected in proc.stderr, proc.stdout + proc.stderr
    assert _head(clone) == head and _files(clone.path) == before


def test_onto_history_check_is_on_the_commit_shape(source, public_clone):
    """Control for the cases above: a commit with exactly the snapshot shape
    passes the history check, so each refusal there is the one property that
    differs."""
    repo = source[0]
    clone, _ = public_clone
    _next_source_commit(repo)
    _changed_in_place()(clone)
    head = _head(clone)
    proc = _onto(source, clone)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert clone.git("log", "-1", "--format=%P").stdout.strip() == head
    assert "HOTFIX.md" in proc.stdout  # not in the export: removed, and listed
    assert not (clone.path / "HOTFIX.md").exists()


def test_onto_refuses_a_shallow_clone(source, public_clone, tmp_path):
    clone, remote = public_clone
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{remote.path}", str(shallow)],
                   env=clone.env, capture_output=True, check=True)
    proc = _onto(source, Repo(shallow, clone.env))
    assert proc.returncode == 2 and "shallow or partial clone" in proc.stderr, proc.stderr


def test_onto_refuses_a_clone_of_the_private_repository(source, tmp_path):
    repo = source[0]
    private_clone = tmp_path / "private-clone"
    subprocess.run(["git", "clone", "-q", str(repo.path), str(private_clone)],
                   env=repo.env, capture_output=True, check=True)
    proc = _onto(source, Repo(private_clone, repo.env))
    assert proc.returncode == 2 and "holds commits of this repository" in proc.stderr


def test_onto_and_out_are_alternatives_and_onto_stays_outside_the_repo(source, public_clone,
                                                                       tmp_path):
    repo = source[0]
    clone, _ = public_clone
    proc = _onto(source, clone, "--out", str(tmp_path / "other"))
    assert proc.returncode == 2 and "alternatives" in proc.stderr
    proc = _onto(source, Repo(repo.path, repo.env))
    assert proc.returncode == 2 and "outside the repository" in proc.stderr
