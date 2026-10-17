"""Dev tools that write a data root refuse one that is not a dev root.

dev_enable_llm.sh (LLM and factory grants), dev_clean_synthetic_notes.sh
(deletes agent notes) and dev_seed_buoys.py (synthetic buoys) share the
strict check in apps/octo/dev/dev_root.py: on any other root they exit 3
and leave it exactly as it was.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
# A real directory outside ~/.octo-dev, /tmp and /var/tmp (pytest's tmp_path
# sits under /tmp, which the check accepts).
OUTSIDE = Path("/dev/shm")

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or not OUTSIDE.is_dir() or not os.access(OUTSIDE, os.W_OK),
    reason="needs bash and a writable /dev/shm",
)


@pytest.fixture
def non_dev_root():
    root = Path(tempfile.mkdtemp(prefix="octo-not-dev-", dir=OUTSIDE))
    (root / "clients" / "tenant-a").mkdir(parents=True)
    (root / "clients" / "tenant-a" / "telemetry.db").write_bytes(b"left alone")
    (root / "registry.db").write_bytes(b"left alone")
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _snapshot(root: Path) -> list[tuple[str, bytes]]:
    return sorted((str(p.relative_to(root)), p.read_bytes() if p.is_file() else b"<dir>")
                  for p in root.rglob("*"))


@pytest.mark.parametrize("cmd", [
    ["bash", "scripts/dev_enable_llm.sh"],
    ["bash", "scripts/dev_clean_synthetic_notes.sh"],
    [sys.executable, "-B", "scripts/dev_seed_buoys.py"],
], ids=["dev_enable_llm", "dev_clean_synthetic_notes", "dev_seed_buoys"])
def test_a_non_dev_root_is_refused_and_left_untouched(cmd, non_dev_root):
    before = _snapshot(non_dev_root)
    env = dict(os.environ, OCTO_DATA_ROOT=str(non_dev_root), PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True,
                          timeout=120)
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "REFUSING" in proc.stderr
    assert _snapshot(non_dev_root) == before
