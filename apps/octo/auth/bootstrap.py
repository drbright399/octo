"""Initialize a fresh OCTO data root + Phase G.1 super_admin provisioning.

The data root is `apps.octo.auth.config.data_root()`: the OCTO_DATA_ROOT env
var, else the default `config.default_data_root()` (~/octo/data of the
account the process runs as). Point OCTO_DATA_ROOT at a sandbox path for
testing. This module does NOT import data from an earlier install (a tool
for that is not yet implemented). On an existing data root,
`init_data_root()` only adds missing directories and applies the pending
registry migrations; the provision_* helpers refuse to overwrite an
existing key file (unless forced) or operator.

G.1 additions:
  - `provision_mfa_key()` — generate the Fernet key for at-rest MFA encryption
    (written owner-only by `write_secret_file()`, the one way this package
    creates a key file)
  - `provision_super_admin()` — bootstrap the very first super_admin;
    writes operator + a single-use initial-setup magic-link and NOTHING
    else that can authenticate (no password, no TOTP secret, no backup
    codes). The operator sets a password and enrols an authenticator
    themselves in the forced setup wizard.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
import sys
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from apps.octo import paths
from apps.octo.db import connect, transaction
from apps.octo.migration import apply_migration, list_migrations


# ---------------------------------------------------------------------------
# Pending-migration application
#
# Originally `init_data_root()` carried a hardcoded if/elif chain of migration
# numbers that had to be extended every time a new registry-touching migration
# landed. That chain was both fragile (easy to forget — bit us with 021) and
# only ran during explicit `init_data_root()` invocations, never on plain
# server start, so a deployed bundle could be running with a registry.db
# whose schema lagged the code by N migrations.
#
# The helpers below replace that:
#   `_registry_migration_numbers()` discovers the registry-touching forward
#   migrations by scanning the files for `@target: registry` markers; plus
#   migration 001 which predates the marker convention.
#
#   `apply_pending_registry_migrations()` walks those in order and applies
#   any whose number > the DB's `PRAGMA user_version`. Idempotent — each
#   migration sets its own `PRAGMA user_version = N`, so re-runs are no-ops.
#
#   `ensure_registry_migrations_applied()` is the public entrypoint for
#   non-bootstrap callers (i.e. `create_app()` during server start). It
#   opens the connection, calls the helper, closes, returns the list of
#   numbers actually applied (so startup can log).
# ---------------------------------------------------------------------------

_TARGET_REGISTRY_RE = re.compile(r"^--\s*@target:\s*registry\s*$", re.MULTILINE)
_TARGET_PATTERNS_RE = re.compile(r"^--\s*@target:\s*patterns\s*$", re.MULTILINE)
_TARGET_AUDIT_RE    = re.compile(r"^--\s*@target:\s*audit\s*$", re.MULTILINE)


def _registry_migration_numbers() -> list[int]:
    """Return numbers of forward migrations that touch registry.db, in order.

    A migration is considered registry-touching if its body contains a
    `-- @target: registry` marker. Migration 001 predates the marker
    convention (the whole file is the base registry schema) and is
    included unconditionally.
    """
    nums: list[int] = []
    for mig in list_migrations(kind="forward"):
        if mig.number == 1:
            nums.append(1)
            continue
        if _TARGET_REGISTRY_RE.search(mig.sql):
            nums.append(mig.number)
    return nums


def _patterns_migration_numbers() -> list[int]:
    """Return numbers of forward migrations that touch the global
    patterns.db, in order. Discovery by `-- @target: patterns` marker."""
    return [
        mig.number for mig in list_migrations(kind="forward")
        if _TARGET_PATTERNS_RE.search(mig.sql)
    ]


def _global_audit_migration_numbers() -> list[int]:
    """Return numbers of forward migrations that touch the global
    audit.db, in order. Discovery by `-- @target: audit` marker."""
    return [
        mig.number for mig in list_migrations(kind="forward")
        if _TARGET_AUDIT_RE.search(mig.sql)
    ]


def apply_pending_registry_migrations(conn: sqlite3.Connection) -> list[int]:
    """Apply any registry migrations whose number > current user_version.

    Returns the list of migration numbers applied this run. Idempotent:
    each migration's SQL sets `PRAGMA user_version = N` on success, so a
    second call with the same DB returns [].
    """
    applied: list[int] = []
    by_number = {m.number: m for m in list_migrations(kind="forward")}
    for num in _registry_migration_numbers():
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        if current >= num:
            continue
        mig = by_number.get(num)
        if mig is None:
            continue
        # Migration 001 has no @target marker (its content is the prelude);
        # later migrations target="registry" explicitly.
        target = None if num == 1 else "registry"
        apply_migration(conn, mig, target=target)
        applied.append(num)
    return applied


def apply_pending_patterns_migrations(conn: sqlite3.Connection) -> list[int]:
    """Apply any patterns migrations whose number > current user_version.

    Same idempotency contract as `apply_pending_registry_migrations`.
    Used by the bundle-bootstrap path AND the sanitized-pool runtime
    to catch up the patterns.db on every server start (avoiding the
    "live deploy DB lags the code" failure mode we hit on registry.db
    pre-bedrock-auto-migrate).
    """
    applied: list[int] = []
    by_number = {m.number: m for m in list_migrations(kind="forward")}
    for num in _patterns_migration_numbers():
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        if current >= num:
            continue
        mig = by_number.get(num)
        if mig is None:
            continue
        apply_migration(conn, mig, target="patterns")
        applied.append(num)
    return applied


def ensure_patterns_migrations_applied(patterns_db_path: Path | str) -> list[int]:
    """Open the patterns DB and apply any pending forward migrations.

    Parallel to `ensure_registry_migrations_applied` but for the global
    patterns.db (the sanitized cross-tenant pool). Safe to call on
    every server start. Returns numbers applied this run.
    """
    path = Path(patterns_db_path)
    if str(path) == ":memory:":
        return []
    conn = connect(path)
    try:
        return apply_pending_patterns_migrations(conn)
    finally:
        conn.close()


def ensure_registry_migrations_applied(registry_db_path: Path | str) -> list[int]:
    """Open the registry DB and apply any pending forward migrations.

    Safe to call on every server start. The parent directory must already
    exist (callers in production paths create it). Returns the list of
    migration numbers applied — empty when the DB is already up-to-date.
    """
    path = Path(registry_db_path)
    if str(path) == ":memory:":
        # In-memory DBs are per-test; tests that need a populated registry
        # construct it explicitly. No-op here so create_app() can call this
        # unconditionally.
        return []
    conn = connect(path)
    try:
        return apply_pending_registry_migrations(conn)
    finally:
        conn.close()


def init_data_root() -> dict[str, str]:
    root = paths.data_root()
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o750)

    (root / "clients").mkdir(exist_ok=True)
    paths.global_dir().mkdir(exist_ok=True)
    paths.archive_dir().mkdir(exist_ok=True)
    paths.backups_dir().mkdir(exist_ok=True)

    # registry.db — apply any pending forward migrations whose body declares
    # `-- @target: registry` (plus migration 001 which is the base schema).
    # `apply_pending_registry_migrations()` is also invoked from
    # `create_app()` on every server start, so a deployed bundle running an
    # older registry.db will catch up the next time the process restarts.
    # Idempotent — each migration sets its own `PRAGMA user_version = N`,
    # so a second run is a no-op.
    reg = connect(paths.registry_db_path())
    try:
        apply_pending_registry_migrations(reg)
    finally:
        reg.close()

    # global/patterns.db + global/audit.db — base schema (migration 003) ONLY
    # on a fresh file. Migration 003 ends with `PRAGMA user_version = 3`, so
    # re-applying it to a live DB silently rewound patterns.db from v24 to v3;
    # the next app start then re-ran migration 023 and died on "duplicate
    # column name: tenant_hmacs" (caught + logged, DB stuck). That made a
    # bootstrap re-run — documented as idempotent, and natural after a restore —
    # quietly destructive. Later migrations are applied by the
    # ensure_*_migrations_applied() catch-up at every start.
    for db_path, target in (
        (paths.patterns_db_path(), "patterns"),
        (paths.global_audit_db_path(), "audit"),
    ):
        conn = connect(db_path)
        try:
            if conn.execute("PRAGMA user_version").fetchone()[0] == 0:
                for mig in list_migrations(kind="forward"):
                    if mig.number == 3:
                        apply_migration(conn, mig, target=target)
        finally:
            conn.close()

    return {
        "data_root": str(root),
        "registry_db": str(paths.registry_db_path()),
        "patterns_db": str(paths.patterns_db_path()),
        "global_audit_db": str(paths.global_audit_db_path()),
    }


# ---------------------------------------------------------------------------
# Key files — written owner-only, published atomically
# ---------------------------------------------------------------------------

SECRET_FILE_MODE = 0o600
SECRET_DIR_MODE = 0o700


def write_secret_file(path: Path, text: str, *, replace: bool = False) -> None:
    """Write a key file (an MFA / HMAC master key) readable by its owner only.

    These keys have to sit on disk in usable form — they are what the
    service decrypts / keys everything else with at start-up — so the file's
    mode and how it comes into existence ARE the protection:

    - The temp file is created by ``os.open(O_CREAT | O_EXCL, 0o600)``: the
      mode is set by the call that creates it (a umask can only narrow it),
      so the key is never readable by another local user, not even briefly.
      (``write_text()`` then ``chmod()`` created it 0644 under the usual
      umask: anyone who opened it in that window kept a readable handle.)
      O_EXCL also refuses a file or symlink planted at the temp name.
    - A directory this creates is 0700; an existing one is left as it is.
    - The content is fsynced before it is published, so a crash leaves the
      old file or the complete new one — never a truncated key.
    - ``replace=False`` publishes with ``os.link``, which fails when `path`
      exists: a key provisioned concurrently is never overwritten (losing
      the MFA key destroys every operator's TOTP secret). FileExistsError.
    - ``replace=True`` — a deliberate rotation — swaps it in with
      ``os.replace``.
    """
    path.parent.mkdir(mode=SECRET_DIR_MODE, parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.new.{uuid.uuid4().hex[:8]}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, SECRET_FILE_MODE)
    try:
        try:
            # Exactly 0600 whatever the umask (it can only have narrowed it).
            os.fchmod(fd, SECRET_FILE_MODE)
            data = memoryview(text.encode("utf-8"))
            while data:
                data = data[os.write(fd, data):]
            os.fsync(fd)
        finally:
            os.close(fd)
        if replace:
            os.replace(tmp, path)
        else:
            os.link(tmp, path)
            # Drop the temp name BEFORE the directory fsync, so a crash
            # right after cannot leave a second name for the key behind.
            os.unlink(tmp)
        _fsync_dir(path.parent)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass        # already published (replaced / linked + unlinked)


def _fsync_dir(directory: Path) -> None:
    """Make a rename / link in `directory` durable (best effort)."""
    try:
        dfd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dfd)
    except OSError:
        pass
    finally:
        os.close(dfd)


# ---------------------------------------------------------------------------
# Phase G.1 — MFA-key provisioning (one-shot, deploy-time)
# ---------------------------------------------------------------------------

def provision_mfa_key(*, force: bool = False) -> dict[str, str]:
    """Generate a new Fernet key and write it to the MFA-key file.

    Refuses to overwrite an existing key unless `force=True` (which is a
    deliberate, audited rotation operation — losing the prior key destroys
    every operator's TOTP secret + backup codes).

    Returns a dict with `path`, `version`, and `bytes_written`. The plaintext
    key is NOT returned — it lives only in the file (perms 600, created that
    way by `write_secret_file`). It is a random 32-byte key, not a password:
    the service needs it in usable form at start-up to decrypt TOTP secrets,
    so the protection is the owner-only file (an encrypted copy would only
    move the problem to the key that decrypts it).
    """
    from apps.octo.auth import crypto

    path = crypto.mfa_key_path()
    already = (
        f"MFA key already exists at {path}. Refusing to overwrite. "
        "Pass --force to deliberately rotate (this destroys all existing "
        "TOTP secrets and backup codes — operators must re-enroll)."
    )
    if path.exists() and not force:
        raise FileExistsError(already)
    key = crypto.generate_mfa_key()                # urlsafe-b64 32 bytes
    text = (
        "MFA_KEY_VERSION=v1\n"
        f"MFA_KEY_BASE64={key.decode()}\n"
    )
    try:
        write_secret_file(path, text, replace=force)
    except FileExistsError:
        if not os.path.lexists(path):
            raise           # not the key (e.g. a file where the dir should be)
        # Created by someone else after the check above: theirs stands.
        raise FileExistsError(already) from None
    return {
        "path": str(path),
        "version": "v1",
        "bytes_written": str(len(text)),
    }


# ---------------------------------------------------------------------------
# Phase G.1 — super_admin bootstrap
# ---------------------------------------------------------------------------

# Imports deferred to function bodies because crypto + auth depend on the
# data root + MFA key file being present, which is only true after a
# successful init_data_root() + provision_mfa_key().

_MAGIC_LINK_TTL_INITIAL_SETUP = timedelta(hours=24)


def _iso_now() -> str:
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _iso_offset(td: timedelta) -> str:
    dt = datetime.now(timezone.utc) + td
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def provision_super_admin(
    *,
    username: str,
    email: str,
    rp_origin: str | None = None,
    actor: str = "system",
    reason: str | None = None,
) -> dict:
    """Bootstrap a fresh super_admin operator — magic-link-only.

    Creates the operator with BOTH `admin` (OCTO API bearer-token role) AND
    `super_admin` (Athena Console role) and mints exactly ONE credential:

      - A 24h single-use initial-setup magic-link token (plaintext returned
        ONCE; only the hash is persisted)

    Deliberately NOT generated here: a password, a TOTP secret, backup
    codes. The row is left with `password_hash IS NULL`, `mfa_enabled = 0`,
    `must_change_password = 1`, so:

      - `/auth/password/begin` can never verify (no hash → generic reject,
        no failed-login bump, so no lockout DoS either);
      - the session the magic link yields is confined by the setup gate
        until the operator has BOTH set a password AND enrolled TOTP by
        scanning the QR (proving possession of an authenticator). Backup
        codes are issued by `/auth/totp/enroll/complete`.

    `operators.create_operator` also mints an admin bearer token; only its
    hash is stored and the plaintext is intentionally dropped here — bearer
    auth is exempt from the setup gate, so it must never be surfaced.

    Refuses if an operator with the same username already exists — bootstrap
    is one-shot per identity.
    """
    import json

    from apps.octo.auth import core as core_auth
    from apps.octo.auth import operators
    from apps.octo.auth.config import athena_origin

    rp_origin = rp_origin or athena_origin()

    # Step 1 — create the operator (its bearer-token plaintext is discarded).
    op = operators.create_operator(
        username=username,
        email=email,
        role="admin",
        scope_slugs=["*"],
        actor=actor,
        reason=reason or "G.1 super_admin bootstrap",
    )
    op_id = op["operator_id"]

    # Step 2 — mint the initial-setup magic-link token (the ONLY credential).
    magic_token_plain = secrets.token_urlsafe(32)
    magic_token_hash = core_auth.hash_token(magic_token_plain)
    issued_at = _iso_now()
    expires_at = _iso_offset(_MAGIC_LINK_TTL_INITIAL_SETUP)
    magic_link_url = (
        rp_origin.rstrip("/")
        + "/login/magic?token="
        + urllib.parse.quote(magic_token_plain, safe="")
    )

    # Step 3 — persist: pre-setup operator state, magic-link row, super_admin
    # role assignment. All under one transaction.
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                "UPDATE operators SET password_hash = NULL, "
                "password_changed_at = NULL, must_change_password = 1, "
                "mfa_enabled = 0, mfa_secret_enc = NULL WHERE id = ?",
                (op_id,),
            )
            reg.execute(
                "INSERT OR IGNORE INTO operator_roles "
                "(operator_id, role_name, scope_slugs) VALUES (?, ?, ?)",
                (op_id, "super_admin", json.dumps(["*"])),
            )
            reg.execute(
                "INSERT INTO magic_link_tokens "
                "(token_hash, operator_id, issued_at, expires_at, purpose) "
                "VALUES (?, ?, ?, ?, ?)",
                (magic_token_hash, op_id, issued_at, expires_at, "initial-setup"),
            )
    finally:
        reg.close()

    # Audit (separate connection — the audit module manages its own tx).
    from apps.octo.auth import audit
    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor=actor,
            actor_kind="human" if actor != "system" else "system",
            action="g1_bootstrap_super_admin",
            target_kind="operator",
            target_id=str(op_id),
            client_slug="global",
            after_state={
                "username": username,
                "email": email,
                "must_change_password": True,
                "password_set": False,
                "mfa_enabled": False,
                "magic_link_expires_at": expires_at,
                "backup_codes_issued": 0,
                "athena_role": "super_admin",
            },
            reason=reason or "G.1 super_admin bootstrap",
            request_id=str(uuid.uuid4()),
        ))
    finally:
        g_audit.close()

    return {
        "operator_id": op_id,
        "username": username,
        "email": email,
        "magic_link_url": magic_link_url,
        "magic_link_expires_at": expires_at,
        "must_change_password": True,
    }


def stage_pending_super_admin(
    *,
    username: str,
    email: str,
    actor: str = "system",
    reason: str | None = None,
) -> dict:
    """Create a `super_admin` operator row in PENDING state.

    Used when a super_admin can't be bootstrapped up front — e.g., a second
    super_admin unavailable at deploy time. The operator row exists with
    `admin` (OCTO API) + `super_admin` (Athena Console) roles, but:

      - `password_hash IS NULL`        — no password login
      - `mfa_enabled = 0`              — no TOTP enrolled
      - no `magic_link_tokens` row     — no inbound auth path
      - no `backup_code_sets` row      — no recovery codes

    The account is inert until activated. Activation: a logged-in super_admin
    issues a magic-link for this operator via `POST /api/v1/auth/magic-link/
    request` (15min TTL); the target consumes it, lands in the Console, and
    self-enrolls factors in Settings.

    Returns the operator_id and the admin bearer token (which CAN be used
    against the OCTO admin API immediately if needed for CLI work — that's
    independent of Console login).
    """
    from apps.octo.auth import operators
    op = operators.create_operator(
        username=username,
        email=email,
        role="admin",
        scope_slugs=["*"],
        actor=actor,
        reason=reason or "G.1 pending super_admin (deferred activation)",
    )
    op_id = op["operator_id"]

    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                "INSERT OR IGNORE INTO operator_roles "
                "(operator_id, role_name, scope_slugs) VALUES (?, ?, ?)",
                (op_id, "super_admin", json.dumps(["*"])),
            )
    finally:
        reg.close()

    from apps.octo.auth import audit
    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor=actor,
            actor_kind="human" if actor != "system" else "system",
            action="g1_stage_pending_super_admin",
            target_kind="operator",
            target_id=str(op_id),
            client_slug="global",
            after_state={
                "username": username,
                "email": email,
                "athena_role": "super_admin",
                "state": "pending",
                "must_activate_via_magic_link": True,
            },
            reason=reason or "G.1 pending super_admin (deferred activation)",
            request_id=str(uuid.uuid4()),
        ))
    finally:
        g_audit.close()

    return {
        "operator_id": op_id,
        "username": username,
        "email": email,
        "admin_bearer_token": op["plaintext"],
        "state": "pending",
        "activation_path": (
            "logged-in super_admin → POST /api/v1/auth/magic-link/request "
            "with target_username=" + username
        ),
    }


# ---------------------------------------------------------------------------
# Factory super_admin — per-MSP-bundle bootstrap (Option 2 architecture)
#
# Each deployed Athena/OCTO bundle gets exactly one factory super_admin on
# first init when no operators exist. It is MAGIC-LINK-ONLY: there is no
# default password and no pre-generated 2FA material. The MSP customer takes
# ownership by opening the printed single-use link, setting a password, and
# enrolling an authenticator (QR) in the forced setup wizard. From then on,
# the credential is theirs to track — Micro IT does not store it.
#
# The factory account IS the break-glass for self-hosted bundles: physical
# host access plus the recovery CLI (`reset_factory_super_admin`, wired as
# `python -m apps.octo.bundle_bootstrap --reset-factory-admin`) lets an MSP
# recover a locked-out bundle without contacting Micro IT.
# ---------------------------------------------------------------------------

FACTORY_SUPER_ADMIN_USERNAME = "Root"
# Placeholder — undeliverable on purpose. `/auth/password/forgot` refuses to
# mint a reset token while this is still the account's email.
FACTORY_SUPER_ADMIN_EMAIL = "root@athena.local"

_FACTORY_RESET_COMMAND = (
    "docker compose run --rm octo-core "
    "python -m apps.octo.bundle_bootstrap --reset-factory-admin"
)


def provision_factory_super_admin_if_empty(
    *,
    print_credentials: bool = True,
) -> dict | None:
    """Provision the factory super_admin if and only if the operators table
    is empty. Idempotent — returns the setup dict on first run, or None if
    any operator already exists (existing accounts are never touched).

    The account is created with NO usable password, NO TOTP secret and NO
    backup codes (`password_hash IS NULL`, `mfa_enabled = 0`,
    `must_change_password = 1`). The ONLY way in is the single-use 24h
    initial-setup magic link; the session it yields is held in the setup
    wizard until a password is set AND an authenticator is enrolled.

    The username + link are printed to stdout in a clearly-bounded block
    so the MSP customer can grab them from the bootstrap terminal. Set
    `print_credentials=False` to suppress (e.g., in tests).
    """
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        existing = reg.execute("SELECT COUNT(*) FROM operators").fetchone()[0]
    finally:
        reg.close()
    if existing > 0:
        return None

    creds = provision_super_admin(
        username=FACTORY_SUPER_ADMIN_USERNAME,
        email=FACTORY_SUPER_ADMIN_EMAIL,
        actor="system",
        reason="factory super_admin (first-init, no operators existed)",
    )
    creds["is_factory_super_admin"] = True

    # Set the persistent is_factory flag on the operator row so
    # code paths can reliably identify this account regardless of
    # any subsequent rename. Migration 026 added the column +
    # backfilled it for existing factory accounts; this is the
    # forward path for fresh first-init.
    reg = connect(paths.registry_db_path())
    try:
        try:
            reg.execute(
                "UPDATE operators SET is_factory = 1 WHERE id = ?",
                (creds["operator_id"],),
            )
            reg.commit()
        except sqlite3.OperationalError:
            # Pre-migration-026 schema — column doesn't exist yet.
            # The username-backfill path in 026 will catch this
            # operator on first auto-migrate. Don't crash first-init.
            pass
    finally:
        reg.close()
    creds["recovery_note"] = (
        f"This is the FACTORY super_admin ({FACTORY_SUPER_ADMIN_USERNAME!r}) "
        f"for this Athena bundle. It has no password and no 2FA yet: the "
        f"single-use magic link (valid 24h) is the only way in. Opening it "
        f"starts the setup wizard, which requires you to set a password and "
        f"then enrol an authenticator app by scanning a QR code; backup "
        f"codes are shown once enrolment completes. If the link expires or "
        f"the account is ever locked out, run the host-side recovery "
        f"command `{_FACTORY_RESET_COMMAND}` — it clears the password, MFA "
        f"and all sessions and prints a fresh link."
    )

    if print_credentials:
        _print_factory_credentials(creds)

    return creds


def _print_factory_credentials(creds: dict) -> None:
    """Print the factory setup block, clearly bounded so it's findable in
    the bootstrap terminal without being mistaken for normal output.

    Contains exactly one secret: the single-use magic link. No password,
    TOTP secret or backup codes exist at this point, so none are printed."""
    bar = "=" * 78
    print(f"\n{bar}", flush=True)
    print("FACTORY SUPER_ADMIN PROVISIONED — OPEN THE SETUP LINK BELOW", flush=True)
    print("There is no default password. The link is the only way in.", flush=True)
    print(bar, flush=True)
    print(f"  Username:           {creds['username']}", flush=True)
    print(f"  Setup link:         {creds['magic_link_url']}", flush=True)
    print(f"  Link expires:       {creds['magic_link_expires_at']}  (single use, 24h)", flush=True)
    print(bar, flush=True)
    _print_link_qr(creds["magic_link_url"])
    print("Next steps:", flush=True)
    print("  1. Open the link in a browser — click it, or scan the QR above", flush=True)
    print("     with a phone.", flush=True)
    print("  2. Set a password (12+ characters).", flush=True)
    print("  3. Scan the QR code with an authenticator app and enter the code;", flush=True)
    print("     save the backup codes shown afterwards.", flush=True)
    print("The console stays locked to this wizard until steps 2 AND 3 are done.", flush=True)
    print("Treat the link like a password until it is used. Link expired or lost?", flush=True)
    print(f"  {_FACTORY_RESET_COMMAND}", flush=True)
    print(f"{bar}\n", flush=True)


def _print_link_qr(url: str) -> None:
    """Render the setup link as a terminal QR so the installer can finish
    first-run from a phone instead of copying a long URL out of a terminal.

    On a TTY: one module = two full character cells painted with explicit
    ANSI black/white BACKGROUNDS. Half-block glyphs (the compact form) were
    unscannable in practice — any terminal line-spacing slices gaps through
    the modules, and foreground glyphs depend on the theme. Background
    colours fill the whole cell and ignore the theme. 4-module quiet zone
    per the QR spec. Not a TTY (captured output): compact glyph fallback.

    Best-effort: the link itself is always printed above, so a missing QR
    library or an odd terminal must never fail the bootstrap."""
    try:
        import qrcode
        qr = qrcode.QRCode(border=4, error_correction=qrcode.constants.ERROR_CORRECT_M)
        qr.add_data(url)
        qr.make(fit=True)
        if sys.stdout.isatty():
            white, black, reset = "\x1b[47m  ", "\x1b[40m  ", "\x1b[0m"
            for row in qr.get_matrix():
                print("".join(black if cell else white for cell in row) + reset)
            print("  Note: this terminal QR may not scan on every screen (window size,", flush=True)
            print("  resolution and font spacing can distort it). That is fine — you are", flush=True)
            print("  not stuck: open the setup link above instead. The 2FA QR code shown", flush=True)
            print("  later inside the setup wizard is a normal image and scans reliably.", flush=True)
        else:
            qr.print_ascii(invert=True)
        sys.stdout.flush()
    except Exception:  # noqa: BLE001 — cosmetic; never block first-run
        try:
            print("  (QR unavailable in this terminal — use the link above)", flush=True)
        except Exception:  # noqa: BLE001 — stdout itself is gone
            pass


def _find_factory_operator(reg: sqlite3.Connection) -> sqlite3.Row | None:
    """Factory row by the persistent `is_factory` flag (survives a rename);
    username fallback for pre-migration-026 schemas / unflagged rows."""
    try:
        row = reg.execute(
            "SELECT id, username FROM operators WHERE is_factory = 1 "
            "ORDER BY id LIMIT 1",
        ).fetchone()
    except sqlite3.OperationalError:
        row = None
    if row is None:
        row = reg.execute(
            "SELECT id, username FROM operators WHERE username = ?",
            (FACTORY_SUPER_ADMIN_USERNAME,),
        ).fetchone()
    return row


def reset_factory_super_admin() -> dict:
    """Break-glass recovery: return the factory super_admin to its pre-setup
    (magic-link-only) state and mint a fresh initial-setup magic link. Used
    when the first link expired, or the MSP lost the factory password /
    authenticator and has no other super_admin to help.

    Requires shell access to the bundle host. In one transaction it:

      - clears the password (`password_hash = NULL`) and lockout state,
        and sets `must_change_password = 1`;
      - clears MFA (`mfa_enabled = 0`, secret dropped), revokes active
        backup-code sets and registered passkeys;
      - burns every still-unused magic-link token for the account, so an
        old printed link stops working;
      - re-enables the account (`disabled_at = NULL`) and re-grants
        `super_admin` — another super_admin may have disabled or demoted
        the factory account before leaving; without this the documented
        recovery prints a link that burns on use (423) or lands in a
        console the operator cannot administer. Host shell access IS the
        authorization for both.

    then revokes all of the account's sessions. The new link forces the
    same wizard as first boot: set password, then enrol TOTP via QR.
    The reset itself uses no MFA-key crypto; completing TOTP enrolment
    afterwards still needs a readable `mfa-key.env`.

    Returns the new magic-link URL + expires_at (the caller prints them).
    Audit-logged with action='factory_recovery_initiated'.
    """
    from apps.octo.auth import core as core_auth
    from apps.octo.auth import sessions

    reg = connect(paths.registry_db_path())
    try:
        row = _find_factory_operator(reg)
        if row is None:
            raise RuntimeError(
                f"factory super_admin '{FACTORY_SUPER_ADMIN_USERNAME}' does "
                "not exist on this bundle — was it ever provisioned?",
            )
        op_id = row["id"]
        op_username = row["username"]
        was_disabled = reg.execute(
            "SELECT disabled_at FROM operators WHERE id = ?", (op_id,),
        ).fetchone()[0] is not None
        had_super_admin = reg.execute(
            "SELECT 1 FROM operator_roles WHERE operator_id = ? "
            "AND role_name = 'super_admin'", (op_id,),
        ).fetchone() is not None

        magic_token_plain = secrets.token_urlsafe(32)
        magic_token_hash = core_auth.hash_token(magic_token_plain)
        issued_at = _iso_now()
        expires_at = _iso_offset(_MAGIC_LINK_TTL_INITIAL_SETUP)

        with transaction(reg):
            # Back to factory state: no password, no MFA, no lockout.
            reg.execute(
                "UPDATE operators SET password_hash = NULL, "
                "password_changed_at = NULL, must_change_password = 1, "
                "mfa_enabled = 0, mfa_secret_enc = NULL, "
                "failed_login_count = 0, locked_until = NULL, "
                "disabled_at = NULL WHERE id = ?",
                (op_id,),
            )
            reg.execute(
                "INSERT INTO operator_roles "
                "(operator_id, role_name, scope_slugs) VALUES (?, ?, ?) "
                "ON CONFLICT(operator_id, role_name) "
                "DO UPDATE SET scope_slugs = excluded.scope_slugs",
                (op_id, "super_admin", json.dumps(["*"])),
            )
            reg.execute(
                "UPDATE backup_code_sets SET revoked_at = ?, "
                "revoke_reason = 'admin-revoke' "
                "WHERE operator_id = ? AND revoked_at IS NULL",
                (issued_at, op_id),
            )
            reg.execute(
                "UPDATE webauthn_credentials SET revoked_at = ? "
                "WHERE operator_id = ? AND revoked_at IS NULL",
                (issued_at, op_id),
            )
            # Burn outstanding links (any purpose) before minting the new one.
            reg.execute(
                "UPDATE magic_link_tokens SET used_at = ? "
                "WHERE operator_id = ? AND used_at IS NULL",
                (issued_at, op_id),
            )
            reg.execute(
                "INSERT INTO magic_link_tokens "
                "(token_hash, operator_id, issued_at, expires_at, purpose) "
                "VALUES (?, ?, ?, ?, ?)",
                (magic_token_hash, op_id, issued_at, expires_at,
                 "initial-setup"),
            )
    finally:
        reg.close()

    sessions_revoked = sessions.revoke_all_for_operator(op_id, revoked_by=None)

    from apps.octo.auth.config import athena_origin
    magic_url = (
        athena_origin().rstrip("/")
        + "/login/magic?token="
        + urllib.parse.quote(magic_token_plain, safe="")
    )

    from apps.octo.auth import audit
    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor="system",
            actor_kind="system",
            action="factory_recovery_initiated",
            target_kind="operator",
            target_id=str(op_id),
            client_slug="global",
            after_state={
                "username": op_username,
                "magic_link_expires_at": expires_at,
                "lockout_cleared": True,
                "must_change_password": True,
                "password_cleared": True,
                "mfa_cleared": True,
                "sessions_revoked": sessions_revoked,
                "re_enabled": was_disabled,
                "super_admin_regranted": not had_super_admin,
            },
            reason="break-glass recovery via reset_factory_super_admin CLI",
            request_id=str(uuid.uuid4()),
        ))
    finally:
        g_audit.close()

    return {
        "username": op_username,
        "magic_link_url": magic_url,
        "magic_link_expires_at": expires_at,
    }
