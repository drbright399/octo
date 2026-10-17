"""Is this data root a local dev root? The one strict check for dev tooling.

A dev-only tool (the synthetic-traffic generator, scripts/dev_seed.py,
scripts/dev_reset_triage.py, scripts/provision_setup_preview.py, and
scripts/start-dev-backend.sh for its dev root and that root's secrets/ and
data/) may only write into a data root that, after resolving symlinks and
`..`, sits under
~/.octo-dev (the dev pair's root, or that directory itself) or strictly
under /tmp or /var/tmp (fixed bases, never $TMPDIR), and is not inside a
production data-root location (/var/lib/octo, the container/bundle layout,
or ~/octo, the single-host layout), even when a dev path leads there. A
substring test ("octo-dev" in the path) is not enough: it accepts a
production path that merely contains the word, and a symlink from a
dev-looking path into a real data root.

Every dev tool uses this module; none keeps its own copy of the rule.
Standard library only, so a standalone script can import it.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union

StrPath = Union[str, "os.PathLike[str]"]

# Fixed system temp roots. Deliberately not tempfile.gettempdir(): that
# follows $TMPDIR, so e.g. TMPDIR=/var/lib/octo would let the production
# data root pass as "a directory under the temp dir".
SYSTEM_TMP_DIRS = ("/tmp", "/var/tmp")

ALLOWED_DESCRIPTION = "~/.octo-dev or a directory under /tmp or /var/tmp"


def production_roots() -> list[Path]:
    """Data-root locations of real deployments, refused even when a dev
    path leads there (e.g. ~/.octo-dev symlinked to one of them)."""
    return [Path("/var/lib/octo").resolve(), (Path.home() / "octo").resolve()]


def _is_under(path: Path, base: Path, *, allow_equal: bool) -> bool:
    if path == base:
        return allow_equal
    return base in path.parents


def dev_root_problem(root: StrPath) -> Optional[str]:
    """None when `root` is a dev data root; otherwise why it is not.

    `root` is resolved here (`~` expanded, symlinks and `..` followed,
    made absolute), so pass the path as configured, not a pre-checked one.
    The reason names the resolved path, never file contents."""
    try:
        resolved = Path(os.fspath(root)).expanduser().resolve()
        dev_home = (Path.home() / ".octo-dev").resolve()
        tmp_dirs = [Path(d).resolve() for d in SYSTEM_TMP_DIRS]
        prods = production_roots()
    except (OSError, RuntimeError):
        # A symlink loop, or no resolvable home: not provably a dev root.
        return "data root (or the home directory) cannot be resolved"
    if not (
        _is_under(resolved, dev_home, allow_equal=True)
        or any(_is_under(resolved, tmp, allow_equal=False) for tmp in tmp_dirs)
    ):
        return (
            f"data root resolves to {str(resolved)!r}, which is not under "
            f"{ALLOWED_DESCRIPTION}"
        )
    for prod in prods:
        if _is_under(resolved, prod, allow_equal=True):
            return (
                f"data root resolves to {str(resolved)!r}, inside the "
                f"production data-root location {str(prod)!r}"
            )
    return None


def is_dev_data_root(root: StrPath) -> bool:
    """True only when `dev_root_problem(root)` finds nothing wrong."""
    return dev_root_problem(root) is None
