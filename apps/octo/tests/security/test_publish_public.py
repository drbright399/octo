"""scripts/publish_public.sh: allowlist export, replacement map, the --publish
scan that refuses, and the single noreply orphan commit that is never pushed."""
from __future__ import annotations

import subprocess

import pytest

from apps.octo.tests.security import fakes
from apps.octo.tests.security.conftest import REPO_ROOT

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
                          cwd=repo.path, env=repo.env, capture_output=True, text=True)


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
        "Athena-OCTO <noreply@users.noreply.github.com>|"
        "Athena-OCTO <noreply@users.noreply.github.com>|")  # no parent: an orphan
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
    ({"PUBLISH_AUTHOR_EMAIL": "rick.noreply@" + "clientcorp.com"}, "GitHub noreply address"),
    ({"PUBLISH_AUTHOR_EMAIL": "zebra-clinic@users.noreply.github.com"}, "local-block term"),
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
                          env=dict(repo.env, **env), capture_output=True, text=True)
    assert proc.returncode == 2 and expected in proc.stderr, proc.stderr
    assert not (tmp_path / "public").exists()


def test_the_snapshot_is_dated_in_utc(source, tmp_path):
    repo, allow, block, mapping = source
    out = tmp_path / "public"
    proc = subprocess.run(["bash", str(PUBLISH), "--repo", str(repo.path), "--allowlist", str(allow),
                           "--local-block", str(block), "--map", str(mapping), "--out", str(out)],
                          env=dict(repo.env, TZ="America/Chicago"), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    raw = subprocess.run(["git", "-C", str(out), "cat-file", "commit", "HEAD"], env=repo.env,
                         capture_output=True, text=True, check=True).stdout
    author = next(line for line in raw.splitlines() if line.startswith("author "))
    committer = next(line for line in raw.splitlines() if line.startswith("committer "))
    assert author.endswith(" +0000") and committer.endswith(" +0000")
