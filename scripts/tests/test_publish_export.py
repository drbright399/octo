"""scripts/publish_export.py: the hard-exclude list wins over any allowlist.

Working notes, agent state, everything under ops/ (host trees, deploy files,
the allowlist itself), host access and infrastructure state, key / vault /
database / backup files and the local terms and map files are never
exported, even when an allowlist selects them. The repo's own allowlist must
cover every script the OCTO image copies, so a public copy builds.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
REPO_ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

import publish_export as pe  # noqa: E402

NEVER = [
    # working notes and agent state
    "STATE.md",
    "apps/octo/STATE.md",
    "docs/handoffs/2026-01-02-handoff.md",
    "docs/design-handoff/2026-01-02-v3-state.md",
    "docs/reviews/round-1/synthesis.md",
    "docs/PRE-PUBLIC-SCRUB.md",
    "docs/sessions/2026-01-02-notes.md",
    "docs/leak-events/2026-01-02-example.md",
    "docs/internal/runbook.md",
    "apps/octo/internal/notes.py",
    "docs/INTERNAL-plan.md",
    ".claude/settings.json",
    "apps/athena/.claude/worktrees/x/README.md",
    # ops/: host trees, deploy files, the allowlist itself
    "ops/README.md",
    "ops/bundle-host/nightly-backup.seal-step.patch.md",
    "ops/public/allowlist.txt",
    "ops/backup-vault/install.sh",
    "ops/bundle-host/docker-compose.yml",
    "ops/legacy-host/backup-databases.timer",
    "ops/octo-bundle/docker-compose.yml.template",
    # host access and infrastructure state
    ".ssh/config",
    "deploy/known_hosts",
    "deploy/authorized_keys.line.template",
    "infra/terraform.tfstate",
    "infra/terraform.tfstate.backup",
    "infra/prod.tfvars",
    "vpn/site.ovpn",
    "k8s/kubeconfig",
    "k8s/prod.kubeconfig",
    "backups/20260102T020000Z.tar.age",
    # local terms, map, secrets, keys, databases, backups
    ".githooks/.local-block",
    ".githooks/.publish-map",
    ".env",
    "apps/octo/.env.local",
    "deploy/prod.env",
    "vault.gpg",
    "keys/tls.pem",
    "keys/tls.key",
    "keys/id_ed25519.pub",
    "secrets/token.txt",
    "credentials/vendor.json",
    "data/registry.db",
    "data/registry.db-wal",
    "data/events.sqlite",
    "data/dump.bak",
]

PUBLIC = [
    "README.md",
    "LICENSE",
    "NOTICE",
    "docs/architecture.md",
    "docs/sample-data/alerts.json",
    "docs/adrs/0001-fleet-map-basemap.md",
    "apps/octo/api/__init__.py",
    "apps/octo/dev/dev_root.py",
    "apps/octo/buoy/buoy-heartbeat.service",
    "apps/octo/adapters/datto/inventory.py",
    "scripts/publish_export.py",
    "scripts/dev.sh",
    "scripts/tests/test_publish_export.py",
    "packages/shared-bridge/pyproject.toml",
]


@pytest.mark.parametrize("path", NEVER)
def test_hard_excluded(path):
    assert pe.hard_excluded(path), path


@pytest.mark.parametrize("path", PUBLIC)
def test_product_paths_are_not_hard_excluded(path):
    assert not pe.hard_excluded(path), path


def _git_env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", HOME=str(home),
               GIT_AUTHOR_NAME="Alice Example", GIT_AUTHOR_EMAIL="alice@example.com",
               GIT_COMMITTER_NAME="Alice Example", GIT_COMMITTER_EMAIL="alice@example.com")
    return env


def test_an_allow_everything_list_still_exports_no_hard_excluded_file(tmp_path, monkeypatch,
                                                                      capsys):
    env = _git_env(tmp_path)
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key)
    for key in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "HOME"):
        monkeypatch.setenv(key, env[key])
    repo = tmp_path / "repo"
    repo.mkdir()
    for rel in NEVER + PUBLIC:
        f = repo / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"synthetic content of {rel}\n")

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True)

    git("init", "-q", "-b", "main")
    git("add", "-A", "--force")  # .env, *.key and friends are gitignored in real repos
    git("commit", "-q", "--no-verify", "-m", "fixture")
    allow = tmp_path / "allowlist.txt"
    allow.write_text("# everything\n**\n")
    out = tmp_path / "export"

    assert pe.main(["--repo", str(repo), "--allowlist", str(allow), "--out", str(out)]) == 0
    printed = capsys.readouterr()
    exported = sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file())
    assert exported == sorted(PUBLIC)
    assert printed.out.split() == sorted(PUBLIC)
    for rel in NEVER:
        assert f"hard-excluded (allowlisted, never published): {rel}" in printed.err
    assert f"{len(PUBLIC)} file(s) selected" in printed.err
    assert f"{len(NEVER)} hard-excluded" in printed.err


def _dockerfile_copied_files() -> list[str]:
    """Repo-relative FILES the OCTO image COPYs by name. A copied directory
    (apps/, the packages) is published through its own allowlist lines and
    copies whatever the public copy holds."""
    text = (REPO_ROOT / "apps" / "octo" / "Dockerfile").read_text()
    copied: list[str] = []
    for line in text.replace("\\\n", " ").splitlines():
        words = line.split()
        if words[:1] != ["COPY"] or any(w.startswith("--from") for w in words):
            continue
        copied += [w for w in words[1:-1]
                   if not w.startswith("--") and not (REPO_ROOT / w).is_dir()]
    return copied


@pytest.mark.skipif(not (REPO_ROOT / "ops" / "public" / "allowlist.txt").is_file(),
                    reason="a public copy carries no allowlist")
def test_the_allowlist_covers_every_file_the_octo_image_copies():
    rules = pe.load_allowlist(REPO_ROOT / "ops" / "public" / "allowlist.txt")
    copied = _dockerfile_copied_files()
    assert "scripts/backup_databases.py" in copied  # the parser sees the scripts
    missing = [path for path in copied
               if not pe.allowed(path, rules) or pe.hard_excluded(path)]
    assert missing == [], "the public copy's docker build would fail on COPY"


@pytest.mark.skipif(not (REPO_ROOT / "ops" / "public" / "allowlist.txt").is_file(),
                    reason="a public copy carries no allowlist")
def test_the_allowlist_names_no_hard_excluded_file():
    """A line the hard-exclude list overrides is a dead promise: drop it."""
    for raw in (REPO_ROOT / "ops" / "public" / "allowlist.txt").read_text().splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "!")) or any(c in line for c in "*?["):
            continue
        assert not pe.hard_excluded(line.rstrip("/")), line
