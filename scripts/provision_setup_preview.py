"""Provision a dev operator that lands on /login/setup.

Use this when you need to *see* the forced first-login wizard end-to-end
on the dev pair. Your normal `dev-admin` account is fully set up
(must_change_password=0, mfa_enabled=1), so navigating to /login/setup
immediately redirects you out.

This script creates (or re-resets) an operator named `setup-preview` with:
  - password_hash set to a random temp password (new on every run)
  - must_change_password = 1   (stage 1 fires)
  - mfa_enabled         = 0    (stage 2 fires after stage 1)
  - mfa_secret_enc      = NULL (no leftover TOTP)
  - role = admin               (smaller blast radius than super_admin)

The temp password is never printed or logged: it is written to a mode-600
file inside the dev data root, and only that file's path is printed.

Then sign in via the real /login form with:
  username: setup-preview
  password: <the temp password in the file whose path this script prints>
(no TOTP prompt — operator has no MFA, /password/begin issues a session
 immediately and setup_gate redirects you to /login/setup.)

Run:
  OCTO_DATA_ROOT=$HOME/.octo-dev/data \
  OCTO_PEPPER_PATH=$HOME/.octo-dev/secrets/pepper.env \
  OCTO_MFA_KEY_PATH=$HOME/.octo-dev/secrets/mfa-key.env \
  packages/.venv/bin/python scripts/provision_setup_preview.py

…or just `scripts/dev.sh` first (which exports those for you in the
shell that started the backend) and then run this script from the
same shell.

To tear down the preview operator (and its temp-password file) when
you're done:
  packages/.venv/bin/python scripts/provision_setup_preview.py --delete

This script is a DEV CONVENIENCE — it does not bypass auth, it just sets
the operator's state to one the wizard knows how to handle. It refuses to
run unless OCTO_DATA_ROOT resolves under ~/.octo-dev, /tmp or /var/tmp
(and never inside /var/lib/octo or ~/octo, where real deployments live),
using the dev-root check every dev tool shares (apps/octo/dev/dev_root.py).
"""
from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path
from typing import NoReturn

# Repo root on sys.path so we can import `apps.octo.*` when running
# the script directly.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PREVIEW_USERNAME = "setup-preview"
PREVIEW_EMAIL = "setup-preview@localhost"
PREVIEW_ROLE = "admin"
# File (inside the dev data root, mode 600) that receives the temp password.
PREVIEW_CREDENTIALS_FILENAME = "setup-preview.temp-password"

from apps.octo import paths
from apps.octo.auth import core as core_auth, operators
from apps.octo.db import connect, transaction
from apps.octo.dev.dev_root import ALLOWED_DESCRIPTION, dev_root_problem


def _refuse(message: str) -> NoReturn:
    sys.stderr.write(f"refuse: {message}\n")
    sys.exit(2)


def _expect_dev_root() -> Path:
    """Refuse to run against a non-dev data root; return the resolved root.

    OCTO_DATA_ROOT must be set, and the root the app resolves from it must
    pass the shared strict check (apps.octo.dev.dev_root): after resolving
    symlinks and `..` it sits under ~/.octo-dev (the dev pair's root) or
    strictly under the fixed /tmp or /var/tmp bases, and not inside a
    production data-root location (/var/lib/octo, ~/octo), even when a dev
    path leads there. A substring match is not enough: it would accept e.g.
    a production path that merely contains "octo-dev".
    """
    raw = os.environ.get("OCTO_DATA_ROOT", "")
    if not raw:
        _refuse(
            "OCTO_DATA_ROOT is not set (the default is the production "
            f"data root). Point it at a dev root under {ALLOWED_DESCRIPTION}."
        )
    # Check the root the app itself resolves (apps.octo.auth.config.data_root):
    # that is where the registry this script writes lives.
    try:
        root = paths.data_root()
    except (OSError, RuntimeError):
        _refuse("OCTO_DATA_ROOT cannot be resolved (a symlink loop?).")
    problem = dev_root_problem(root)
    if problem is not None:
        _refuse(
            f"OCTO_DATA_ROOT: {problem}. This script only makes sense for "
            "the local dev pair."
        )
    return root


def _write_private_file(path: Path, content: str) -> None:
    """Write `content` to a fresh mode-600 file at `path`.

    Any previous file (or a planted symlink) is removed first, and the
    new file is created with O_EXCL so the write never follows a link or
    lands in a file with looser permissions.
    """
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)


def _delete(op_id: int) -> None:
    """Hard-delete the preview operator + its dependent rows.

    Safe for dev only — `_expect_dev_root()` already gated entry. We
    clear the role grant + any sessions + magic-link tokens + backup
    code sets first, then drop the operator row.
    """
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute("DELETE FROM sessions WHERE operator_id = ?", (op_id,))
            reg.execute("DELETE FROM operator_roles WHERE operator_id = ?", (op_id,))
            reg.execute("DELETE FROM magic_link_tokens WHERE operator_id = ?", (op_id,))
            reg.execute("DELETE FROM backup_code_sets WHERE operator_id = ?", (op_id,))
            reg.execute("DELETE FROM operators WHERE id = ?", (op_id,))
    finally:
        reg.close()


def main() -> None:
    data_root = _expect_dev_root()
    credentials_path = data_root / PREVIEW_CREDENTIALS_FILENAME
    delete_mode = "--delete" in sys.argv[1:]

    reg = connect(paths.registry_db_path())
    try:
        row = reg.execute(
            "SELECT id FROM operators WHERE username = ?",
            (PREVIEW_USERNAME,),
        ).fetchone()
    finally:
        reg.close()

    if delete_mode:
        credentials_path.unlink(missing_ok=True)
        if row is None:
            print(f"[provision] no operator named {PREVIEW_USERNAME!r} — nothing to delete")
            return
        _delete(row["id"])
        print(f"[provision] deleted operator id={row['id']} username={PREVIEW_USERNAME}")
        return

    if row is None:
        op = operators.create_operator(
            username=PREVIEW_USERNAME,
            email=PREVIEW_EMAIL,
            role=PREVIEW_ROLE,
            scope_slugs=["*"],
            actor="system",
            reason="dev: provision /login/setup preview operator",
        )
        op_id = op["operator_id"]
        print(f"[provision] created operator id={op_id} username={PREVIEW_USERNAME}")
    else:
        op_id = row["id"]
        print(f"[provision] re-resetting existing operator id={op_id}")

    # Fresh random temp password on every run; the wizard forces a change
    # at first sign-in (must_change_password = 1).
    temp_password = secrets.token_urlsafe(16)
    pw_hash = core_auth.hash_token(temp_password)
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                "UPDATE operators "
                "   SET password_hash = ?, "
                "       must_change_password = 1, "
                "       mfa_enabled = 0, "
                "       mfa_secret_enc = NULL, "
                "       failed_login_count = 0, "
                "       locked_until = NULL, "
                "       disabled_at = NULL "
                " WHERE id = ?",
                (pw_hash, op_id),
            )
    finally:
        reg.close()

    # Hand the temp password over through a private file, never stdout:
    # stdout of dev scripts ends up in terminal scrollback, nohup logs and
    # agent transcripts.
    _write_private_file(credentials_path, temp_password + "\n")

    print("=" * 70)
    print("/login/setup PREVIEW OPERATOR READY")
    print(f"  username: {PREVIEW_USERNAME}")
    print(f"  password: in {credentials_path} (mode 600)")
    print(f"  role:     {PREVIEW_ROLE}")
    print()
    print("Sign in via http://localhost:5173/login — no TOTP prompt;")
    print("the session is gated to /login/setup until you finish the wizard.")
    print()
    print("Re-run this script any time to reset the operator back to step 1")
    print("(with a new temp password); --delete removes the operator and the file.")
    print("=" * 70)


if __name__ == "__main__":
    main()
