"""First-run provisioning for a fresh bundle deploy.

Run ONCE, explicitly, before the first `docker compose up -d`:

    docker compose run --rm octo-core python -m apps.octo.bundle_bootstrap

Steps (each idempotent — an existing file / row is never overwritten):
  1. pepper.env                    (OCTO_PEPPER_PATH — legacy-compat only;
                                    no bedrock code path reads it)
  2. mfa-key.env                   (OCTO_MFA_KEY_PATH)
  3. adapter-credentials-key.env   (OCTO_ADAPTER_CREDENTIALS_KEY_PATH)
     entity-hmac.env               (OCTO_ENTITY_HMAC_PATH — entity tokens)
  4. data root + registry/patterns/audit migrations
  5. factory super_admin — only when the operators table is empty.
     MAGIC-LINK-ONLY: the account has no password and no 2FA material.
     A single-use 24h initial-setup magic link prints to THIS terminal
     exactly once (a `run --rm` one-shot, so it never lands in the
     long-running container's log). Open it, set a password, enrol an
     authenticator by scanning the QR — the console stays locked to that
     wizard until both are done.

Recovery (link expired / lost password or authenticator, no other
super_admin):

    docker compose run --rm octo-core \\
        python -m apps.octo.bundle_bootstrap --reset-factory-admin

returns the factory account to the same pre-setup state (password + MFA
cleared, passkeys/backup codes/sessions revoked, old links burned) and
prints a fresh link. Host shell access is the authorisation.

Deliberately NOT wired into container start: a missing secrets mount must
show as (unhealthy) via /readyz rather than mint a fresh MFA / credentials
key over a live registry — that would silently orphan every TOTP enrolment
and every vaulted vendor credential.
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path
from urllib.parse import urlparse

from apps.octo import credentials, paths
from apps.octo.auth import bootstrap, config


def _nearest_existing(path: Path) -> Path:
    while not path.exists() and path != path.parent:
        path = path.parent
    return path


def preflight() -> list[str]:
    """Problems that must be fixed BEFORE anything is minted. Half a
    bootstrap (keys written, then init_data_root dying on chmod) is worse
    than none, and the factory setup link prints exactly once and is the
    account's ONLY credential — so a magic link built from an empty public
    host must never be issued."""
    problems: list[str] = []
    uid = os.getuid()
    for label, target in (
        ("secrets dir", config.pepper_path().parent),
        ("state dir", paths.data_root()),
    ):
        d = _nearest_existing(target)
        # init_data_root chmods the data root: needs OWNERSHIP, not just
        # write access (a 0777 dir owned by someone else still EPERMs).
        if d.stat().st_uid != uid or not os.access(d, os.W_OK | os.X_OK):
            problems.append(
                f"{label} {d} must be owned + writable by uid {uid} — on the "
                f"host: chown -R {uid}:{os.getgid()} <that mount's host path>"
            )
    rp_id = config.athena_rp_id()
    host = urlparse(config.athena_origin()).hostname or ""
    if not rp_id or rp_id == config.ATHENA_RP_ID_DEFAULT:
        problems.append(
            "ATHENA_RP_ID is empty/default — render the compose file with "
            "BUNDLE_PUBLIC_HOST set"
        )
    elif not (host == rp_id or host.endswith("." + rp_id)):
        problems.append(
            "ATHENA_ORIGIN host does not match ATHENA_RP_ID — passkeys and "
            "the printed magic link would be unusable"
        )
    return problems


def provision_pepper() -> bool:
    """Write pepper.env (mode 600) if absent. Returns True when created.

    Written by `bootstrap.write_secret_file`, like the MFA key: owner-only
    from the moment the file exists (never write-then-chmod), published
    atomically, and NEVER over an existing pepper — including one another
    run provisioned after the check below (theirs stands: replacing a pepper
    invalidates every hash keyed by it)."""
    path = config.pepper_path()
    if path.exists():
        return False
    text = (
        "PEPPER_VERSION=pepper_v1\n"
        f"PEPPER_HEX={secrets.token_hex(32)}\n"
    )
    try:
        bootstrap.write_secret_file(path, text)
    except FileExistsError:
        if not os.path.lexists(path):
            raise           # not the pepper (e.g. a file where the dir should be)
        return False
    return True


def _reset_factory_admin() -> int:
    """--reset-factory-admin: recovery only — provisions nothing."""
    if not paths.registry_db_path().exists():
        print("[bootstrap] no registry on this bundle — run the first-run "
              "bootstrap instead")
        return 1
    try:
        result = bootstrap.reset_factory_super_admin()
    except RuntimeError as exc:
        print(f"[bootstrap] {exc}")
        return 1
    bar = "=" * 78
    print(f"\n{bar}")
    print("FACTORY SUPER_ADMIN RESET — password, MFA and sessions cleared")
    print(bar)
    print(f"  Username:           {result['username']}")
    print(f"  Setup link:         {result['magic_link_url']}")
    print(f"  Link expires:       {result['magic_link_expires_at']}  (single use, 24h)")
    print(bar)
    bootstrap._print_link_qr(result["magic_link_url"])
    print("Open the link (click it, or scan the QR above), set a password, then")
    print("scan the authenticator QR. Any earlier setup link no longer works.")
    print(f"{bar}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--skip-factory-admin", action="store_true",
        help="provision keys + data root only; do not create the factory "
             "super_admin",
    )
    ap.add_argument(
        "--reset-factory-admin", action="store_true",
        help="break-glass: clear the factory super_admin's password, MFA "
             "and sessions, and print a fresh single-use setup link",
    )
    args = ap.parse_args(argv)

    problems = preflight()
    if problems:
        print("[bootstrap] refusing to run — nothing was created:")
        for p in problems:
            print(f"  - {p}")
        return 2

    if args.reset_factory_admin:
        return _reset_factory_admin()

    created = provision_pepper()
    print(f"[bootstrap] pepper: {'created' if created else 'exists'} "
          f"({config.pepper_path()})")

    try:
        bootstrap.provision_mfa_key()
        print("[bootstrap] mfa key: created")
    except FileExistsError:
        print("[bootstrap] mfa key: exists")

    key_path = credentials.ensure_key_file()
    print(f"[bootstrap] adapter credentials key: ok ({key_path})")

    from apps.octo.entity import tokens as entity_tokens

    entity_tokens.master()
    print(f"[bootstrap] entity token key: ok ({entity_tokens.key_path()})")

    info = bootstrap.init_data_root()
    print(f"[bootstrap] data root: ok ({info['data_root']})")

    if args.skip_factory_admin:
        print("[bootstrap] factory super_admin: skipped")
        return 0

    creds = bootstrap.provision_factory_super_admin_if_empty()
    if creds is None:
        print("[bootstrap] factory super_admin: operators already exist — "
              "nothing to do")
    return 0


if __name__ == "__main__":
    sys.exit(main())
