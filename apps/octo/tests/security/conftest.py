"""Throwaway git repositories for the scanner / hook / publish tests.

Every git call runs with the user's global and system config switched off
(no personal hooks, templates, signing or identity leak in), and never
touches this checkout."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
SCANNER = REPO_ROOT / "scripts" / "scan_sensitive.py"

# What a clone needs for the hooks to run: the hooks, the scanner and the
# shared detector module it imports.
GUARDRAIL_FILES = (
    ".githooks/pre-commit",
    ".githooks/commit-msg",
    ".githooks/pre-push",
    ".githooks/lib-scan.sh",
    "scripts/install_hooks.sh",
    "scripts/scan_sensitive.py",
    "apps/__init__.py",
    "apps/octo/__init__.py",
    "apps/octo/security/__init__.py",
    "apps/octo/security/secret_patterns.py",
)


def git_env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") and k != "SCAN_SENSITIVE_LOCAL_BLOCK"}
    env.update(
        GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", HOME=str(home),
        GIT_AUTHOR_NAME="Alice Example", GIT_AUTHOR_EMAIL="alice@example.com",
        GIT_COMMITTER_NAME="Alice Example", GIT_COMMITTER_EMAIL="alice@example.com",
    )
    return env


class Repo:
    def __init__(self, path: Path, env: dict[str, str]) -> None:
        self.path = path
        self.env = env

    def git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        proc = subprocess.run(["git", *args], cwd=self.path, env=self.env,
                              capture_output=True, text=True)
        if check and proc.returncode != 0:
            raise AssertionError(f"git {args}: {proc.stdout}{proc.stderr}")
        return proc

    def write(self, rel: str, text: str) -> Path:
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return target

    def commit(self, rel: str, text: str, message: str = "change",
               no_verify: bool = False) -> subprocess.CompletedProcess:
        self.write(rel, text)
        self.git("add", rel)
        args = ["commit", "-q", "-m", message] + (["--no-verify"] if no_verify else [])
        return self.git(*args, check=False)

    def scan(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(SCANNER), *args], cwd=self.path,
                              env=self.env, capture_output=True, text=True)

    def install_guardrails(self) -> None:
        for rel in GUARDRAIL_FILES:
            dest = self.path / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / rel, dest)
        self.git("config", "core.hooksPath", ".githooks")


@pytest.fixture
def make_repo(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    env = git_env(home)

    def _make(name: str = "repo", *, bare: bool = False) -> Repo:
        path = tmp_path / name
        path.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", *(["--bare"] if bare else [])],
                       cwd=path, env=env, check=True)
        return Repo(path, env)

    return _make
